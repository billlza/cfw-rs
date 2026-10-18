from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.publication import finalize as finalize_module
from scripts.publication import preparer
from scripts.publication.common import PublicationError
from scripts.publication.release_contract import (
    evidence_root,
    prepared_root,
    review_template,
)
from scripts.release_build_identity import ga_root


class StageWorkStopped(Exception):
    pass


class PrivateStageInputsTests(unittest.TestCase):
    """Every publication writer shares the receipt's private stage-input directory."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name).resolve()
        self.ga = ga_root(self.repository)
        self.ga.mkdir(parents=True)
        self.ga.chmod(0o700)
        self.stage_inputs = self.ga / "stage-inputs"
        self.app = self.repository / "Clash for Mac.app"
        previous = os.umask(0o022)
        self.addCleanup(os.umask, previous)

    def writers(self):
        return (
            (
                "review-template",
                (preparer, "load_pins"),
                lambda: preparer.write_review_template(
                    self.repository, self.repository, review_template(self.repository)
                ),
            ),
            (
                "prepare",
                (preparer, "load_pins"),
                lambda: preparer.prepare(
                    self.repository,
                    self.app,
                    self.repository,
                    self.repository / "reviewed-components.json",
                    prepared_root(self.repository),
                ),
            ),
            (
                "finalize",
                (finalize_module, "build_machine_closure"),
                lambda: finalize_module.finalize(
                    self.repository / "publication-prepared",
                    self.app,
                    self.repository / "legal-review.json",
                    evidence_root(self.repository),
                    False,
                    repository=self.repository,
                ),
            ),
        )

    def test_each_writer_creates_private_stage_inputs_before_its_work(self) -> None:
        for name, (module, work), write in self.writers():
            with self.subTest(writer=name):
                if self.stage_inputs.exists():
                    self.stage_inputs.rmdir()
                with patch.object(
                    preparer, "require_fixed_signed_app", return_value=self.app
                ), patch.object(module, work, side_effect=StageWorkStopped):
                    with self.assertRaises(StageWorkStopped):
                        write()
                metadata = self.stage_inputs.lstat()
                self.assertTrue(stat.S_ISDIR(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o700)

    def test_each_writer_rejects_permissive_stage_inputs_before_its_work(self) -> None:
        self.stage_inputs.mkdir()
        self.stage_inputs.chmod(0o755)
        for name, (module, work), write in self.writers():
            with self.subTest(writer=name):
                with patch.object(
                    preparer, "require_fixed_signed_app", return_value=self.app
                ), patch.object(module, work) as started:
                    with self.assertRaisesRegex(PublicationError, "mode is not 0700"):
                        write()
                started.assert_not_called()
                self.assertEqual(stat.S_IMODE(self.stage_inputs.lstat().st_mode), 0o755)


if __name__ == "__main__":
    unittest.main()
