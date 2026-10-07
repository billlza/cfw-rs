"""Every fixed release code inventory follows the canonical signing plan.

native/macos/Config/signing-order.json is the one list of nested code. The
tools that reopen signed bytes keep their own fixed tables, and a component
added to the plan without them fails only after Developer ID signing, which
consumes the build number. These checks compare each table with the plan.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from scripts import verify_signing_transformation as transformation
from scripts.native_ui_artifact import RESOURCES
from scripts.publication.closure import ALLOWED_CODE_PATHS
from scripts.release_app_verifier_output import _expected_codesign_subjects


REPOSITORY = Path(__file__).resolve().parents[2]


class ReleaseCodeInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        plan = json.loads(
            (REPOSITORY / "native/macos/Config/signing-order.json").read_text(encoding="utf-8")
        )
        self.nested = plan["nested"]
        self.outer = plan["outer"]["destination"]

    def test_signing_transformation_normalizes_every_planned_object_in_plan_order(self) -> None:
        self.assertEqual(
            transformation.CODE_OBJECTS,
            (*(item["destination"] for item in self.nested), self.outer),
        )

    def test_publication_code_closure_is_every_planned_executable(self) -> None:
        self.assertEqual(ALLOWED_CODE_PATHS, set(transformation.MACHO_EXECUTABLES))

    def test_release_verifier_transcript_reports_every_planned_executable(self) -> None:
        app = "/fixture/Clash for Mac.app"
        _prepared, _prepared_raw, results = _expected_codesign_subjects(app)
        self.assertEqual(
            {f"{app}/{executable}" for executable in transformation.MACHO_EXECUTABLES}
            - set(results),
            set(),
        )

    def test_signing_helper_promotes_a_manifest_for_every_planned_product(self) -> None:
        helper = (REPOSITORY / "scripts/run_ga_signing_attempt.sh").read_text(encoding="utf-8")
        loop = re.search(
            r"for product in \\\n((?:  \S+ \\\n)*  \S+); do\n  cfw_run_release_python_script \\\n"
            r"    \"\$repo_root\" \\\n    \"\$repo_root/scripts/promote_signed_native_manifest\.py\"",
            helper,
        )
        self.assertIsNotNone(loop)
        promoted = {line.strip().rstrip(" \\") for line in loop.group(1).splitlines()}
        planned = {Path(item["stagedArtifact"]).parts[0] for item in self.nested}
        # The SwiftUI resource bundle has no code of its own; the Host seals it.
        self.assertEqual(promoted, planned | {RESOURCES})


if __name__ == "__main__":
    unittest.main()
