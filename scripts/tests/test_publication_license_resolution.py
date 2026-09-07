from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.publication.common import PublicationError
from scripts.publication.graph_model import ComponentSeed
from scripts.publication.license_resolution import (
    canonical_spdx_expression,
    resolve_license,
    validate_automatic_resolution,
)


MIT_TEXT = """MIT License

Copyright (c) 2026 Fixture Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction.
"""

ISC_COMMENTED_TEXT = """// Copyright 2026 Fixture Authors.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
"""


class LicenseResolutionTests(unittest.TestCase):
    def seed(
        self,
        root: Path,
        *,
        ecosystem: str = "cargo",
        declared_license: str | None = "MIT",
    ) -> ComponentSeed:
        metadata = root / ("go.mod" if ecosystem == "go" else "Cargo.toml")
        metadata.write_text(
            "module example.com/fixture\n"
            if ecosystem == "go"
            else (
                '[package]\nname = "fixture"\nversion = "1.0.0"\n'
                f'license = "{declared_license}"\n'
            ),
            encoding="utf-8",
        )
        return ComponentSeed(
            identifier=f"{ecosystem}:fixture:0000000000000000",
            name="example.com/fixture" if ecosystem == "go" else "fixture",
            version="1.0.0",
            ecosystem=ecosystem,
            scope="runtime",
            purl=f"pkg:{ecosystem}/fixture@1.0.0",
            source_root=root,
            license_root=root,
            metadata_path=metadata,
            declared_license=declared_license,
        )

    def test_declared_spdx_and_source_text_resolve_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
            seed = self.seed(root)
            resolution = resolve_license(seed)
            self.assertEqual(resolution["status"], "automatic")
            self.assertEqual(resolution["expression"], "MIT")
            self.assertEqual(validate_automatic_resolution(seed, resolution), resolution)

    def test_repository_license_does_not_escape_into_hidden_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            license_path = root / "LICENSE"
            license_path.write_text(MIT_TEXT, encoding="utf-8")
            hidden_worktree = root / ".kilo/worktrees/stale"
            hidden_worktree.mkdir(parents=True)
            (hidden_worktree / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")

            resolution = resolve_license(self.seed(root))

            self.assertEqual(resolution["status"], "automatic")
            self.assertEqual(
                [item["path"] for item in resolution["files"]],
                [str(license_path.resolve(strict=True))],
            )

    def test_automatic_evidence_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            license_path = root / "LICENSE"
            license_path.write_text(MIT_TEXT, encoding="utf-8")
            seed = self.seed(root)
            resolution = resolve_license(seed)
            resolution["files"][0]["sha256"] = "0" * 64
            with self.assertRaises(PublicationError):
                validate_automatic_resolution(seed, resolution)
            license_path.write_text("tampered", encoding="utf-8")
            with self.assertRaises(PublicationError):
                validate_automatic_resolution(seed, resolve_license(self.seed(root)))

    def test_missing_declared_license_text_requires_manual_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = self.seed(root, declared_license="MIT AND Apache-2.0")
            (root / "LICENSE-MIT").write_text(MIT_TEXT, encoding="utf-8")
            resolution = resolve_license(seed)
            self.assertEqual(resolution["status"], "manual-required")
            self.assertIn("Apache-2.0", resolution["reason"])
            with self.assertRaises(PublicationError):
                validate_automatic_resolution(seed, resolution)

    def test_one_complete_declared_or_branch_resolves_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = self.seed(root, declared_license="MIT OR Apache-2.0")
            (root / "LICENSE-MIT").write_text(MIT_TEXT, encoding="utf-8")
            resolution = resolve_license(seed)
            self.assertEqual(resolution["status"], "automatic")
            self.assertEqual(resolution["files"][0]["supports"], ["MIT"])

    def test_go_module_identity_and_single_text_are_dual_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
            seed = self.seed(root, ecosystem="go", declared_license=None)
            resolution = resolve_license(seed)
            self.assertEqual(resolution["status"], "automatic")
            self.assertEqual(resolution["expression"], "MIT")

    def test_commented_isc_text_resolves_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = self.seed(root, declared_license="ISC")
            (root / "LICENSE.txt").write_text(ISC_COMMENTED_TEXT, encoding="utf-8")
            resolution = resolve_license(seed)
            self.assertEqual(resolution["status"], "automatic")
            self.assertEqual(resolution["files"][0]["supports"], ["ISC"])

    def test_spdx_identifiers_exceptions_and_local_license_refs_are_validated(self) -> None:
        self.assertEqual(
            canonical_spdx_expression("Apache-2.0 WITH LLVM-exception"),
            "Apache-2.0 WITH LLVM-exception",
        )
        self.assertEqual(
            canonical_spdx_expression("LicenseRef-Apple-Xcode-EULA-26.6"),
            "LicenseRef-Apple-Xcode-EULA-26.6",
        )
        for invalid in (
            "MadeUp-1.0",
            "Apache-2.0 WITH MadeUp-exception",
            "(Apache-2.0 OR MIT) WITH LLVM-exception",
            "LicenseRef-Xcode WITH LLVM-exception",
            "LLVM-exception",
            "LicenseRef-",
            "LicenseRef-Xcode+",
            "DocumentRef-vendor:LicenseRef-Xcode",
            "NOASSERTION",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(PublicationError):
                canonical_spdx_expression(invalid)

    def test_manual_review_preserves_compound_expression_and_full_file_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = self.seed(root, ecosystem="go", declared_license=None)
            license_files = {
                "LICENSE-APACHE": "reviewed Apache terms",
                "LICENSE-BSD": "reviewed BSD terms",
                "LICENSE-MIT": "reviewed MIT terms",
            }
            for name, text in license_files.items():
                (root / name).write_text(text, encoding="utf-8")
            required = resolve_license(seed)
            self.assertEqual(required["status"], "manual-required")
            supports = {
                "LICENSE-APACHE": ["Apache-2.0"],
                "LICENSE-BSD": ["BSD-3-Clause"],
                "LICENSE-MIT": ["MIT"],
            }
            reviewed = {
                **required,
                "status": "manual-reviewed",
                "expression": "BSD-3-Clause AND Apache-2.0 AND MIT",
                "method": "human-legal-review",
                "reason": "The three independently bound license texts all apply.",
                "files": [
                    {**item, "supports": supports[Path(item["path"]).name]}
                    for item in required["files"]
                ],
            }
            validated = validate_automatic_resolution(seed, reviewed)
            self.assertEqual(
                validated["expression"], "BSD-3-Clause AND Apache-2.0 AND MIT"
            )

            incomplete = {
                **reviewed,
                "files": [item for item in reviewed["files"] if item["supports"] != ["MIT"]],
            }
            with self.assertRaisesRegex(PublicationError, "exact expression"):
                validate_automatic_resolution(seed, incomplete)


if __name__ == "__main__":
    unittest.main()
