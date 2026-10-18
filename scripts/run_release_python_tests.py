#!/usr/bin/env python3
"""Run repository release-tool tests from the isolated Python launcher."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
import unittest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pattern", default="test_*.py")
    arguments = parser.parse_args()
    if (
        arguments.pattern != "test_*.py"
        and re.fullmatch(r"test_[a-z0-9_]+[.]py", arguments.pattern) is None
    ):
        raise SystemExit("error: unsupported release-test pattern")
    tests = Path(__file__).resolve().parent / "tests"
    if arguments.pattern != "test_*.py":
        selected = tests / arguments.pattern
        try:
            metadata = selected.lstat()
        except OSError as error:
            raise SystemExit(
                "error: selected release-test file is unavailable"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or selected.is_symlink()
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise SystemExit(
                "error: selected release-test file is not a safe regular source"
            )
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(tests),
        pattern=arguments.pattern,
        top_level_dir=str(tests),
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.testsRun > 0 and result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
