from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import release_regular_file


REPOSITORY = Path(__file__).resolve().parents[2]


class ReleaseRegularFileTests(unittest.TestCase):
    def test_fifo_rebind_is_rejected_without_blocking_in_open(self) -> None:
        script = r"""
import os
from pathlib import Path
import sys
import tempfile

repository = Path(sys.argv[1])
sys.path.insert(0, str(repository))
from scripts.release_regular_file import (
    ReleaseRegularFileError,
    read_bounded_regular_file,
)

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "release-input"
    path.write_bytes(b"stable release input")
    path.chmod(0o644)
    original_open = os.open
    rebound = False

    def rebinding_open(
        target: os.PathLike[str],
        flags: int,
        *arguments: object,
        **keywords: object,
    ) -> int:
        global rebound
        if not rebound and keywords.get("dir_fd") is None and Path(target) == path:
            rebound = True
            path.unlink()
            os.mkfifo(path, 0o600)
        return original_open(target, flags, *arguments, **keywords)

    os.open = rebinding_open
    try:
        read_bounded_regular_file(
            path,
            label="FIFO rebind fixture",
            maximum_bytes=1024,
            allowed_owner_uids=frozenset({os.geteuid()}),
            exact_mode=0o644,
        )
    except ReleaseRegularFileError as error:
        if str(error) != "FIFO rebind fixture changed while opening":
            raise
    else:
        raise RuntimeError("FIFO rebind fixture was accepted")
    if not rebound:
        raise RuntimeError("FIFO rebind fixture did not run")
"""
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-W",
                "error",
                "-c",
                script,
                str(REPOSITORY),
            ],
            check=False,
            capture_output=True,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            timeout=5,
        )

        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace")[-1000:],
        )
        self.assertEqual(completed.stdout, b"")

    def test_short_read_and_read_error_close_the_descriptor(self) -> None:
        for failure in ("short-read", "read-error"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "release-input"
                path.write_bytes(b"stable release input")
                path.chmod(0o644)
                original_close = os.close
                closed: list[int] = []

                def closing(descriptor: int) -> None:
                    closed.append(descriptor)
                    original_close(descriptor)

                def failing_read(_descriptor: int, _count: int) -> bytes:
                    if failure == "short-read":
                        return b""
                    raise OSError("read failed")

                diagnostic = (
                    "changed while reading"
                    if failure == "short-read"
                    else "cannot read release input fixture"
                )
                with (
                    patch(
                        "scripts.release_regular_file.os.read",
                        side_effect=failing_read,
                    ),
                    patch(
                        "scripts.release_regular_file.os.close",
                        side_effect=closing,
                    ),
                    self.assertRaisesRegex(
                        release_regular_file.ReleaseRegularFileError,
                        diagnostic,
                    ),
                ):
                    release_regular_file.read_bounded_regular_file(
                        path,
                        label="release input fixture",
                        maximum_bytes=1024,
                        allowed_owner_uids=frozenset({os.geteuid()}),
                        exact_mode=0o644,
                    )

                self.assertEqual(len(closed), 1)


if __name__ == "__main__":
    unittest.main()
