from __future__ import annotations

import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest

from scripts.verify_candidate_bundle import CandidateError, enumerate_bundle


REPOSITORY = Path(__file__).resolve().parent.parent.parent
BOUNDARY = REPOSITORY / "scripts/release_bundle_codesign.sh"
CODESIGN = "/usr/bin/codesign"


def create_app(root: Path, *, bundle_id: str, executable_name: str) -> Path:
    contents = root / "Contents"
    executable_root = contents / "MacOS"
    resources = contents / "Resources"
    for directory in (root, contents, executable_root, resources):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o755)

    info = contents / "Info.plist"
    with info.open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleExecutable": executable_name,
                "CFBundleIdentifier": bundle_id,
                "CFBundleName": executable_name,
                "CFBundlePackageType": "APPL",
                "CFBundleShortVersionString": "1.0",
                "CFBundleVersion": "1",
            },
            handle,
            sort_keys=True,
        )
    info.chmod(0o644)

    executable = executable_root / executable_name
    shutil.copyfile("/usr/bin/true", executable)
    executable.chmod(0o755)
    resource = resources / "fixture.txt"
    resource.write_bytes(b"distribution mode fixture\n")
    resource.chmod(0o644)
    return root


class ReleaseBundleCodesignTests(unittest.TestCase):
    def test_production_boundary_scopes_distribution_umask_without_leaking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            host = create_app(
                temporary / "Host.app",
                bundle_id="com.bill.codesign-mode-test.host",
                executable_name="Host",
            )
            plugins = host / "Contents/PlugIns"
            plugins.mkdir(mode=0o755)
            nested = create_app(
                plugins / "Nested.app",
                bundle_id="com.bill.codesign-mode-test.nested",
                executable_name="Nested",
            )
            sentinel = temporary / "private-after-codesign"

            command = """
set -euo pipefail
umask 077
source "$1"
cfw_codesign_distribution_bundle --force --sign - --timestamp=none \
  --identifier com.bill.codesign-mode-test.nested "$2"
cfw_codesign_distribution_bundle --force --sign - --timestamp=none \
  --identifier com.bill.codesign-mode-test.host "$3"
: >"$4"
"""
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-p",
                    "-c",
                    command,
                    "release-bundle-codesign-test",
                    str(BOUNDARY),
                    str(nested),
                    str(host),
                    str(sentinel),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            code_resources = (
                nested / "Contents/_CodeSignature/CodeResources",
                host / "Contents/_CodeSignature/CodeResources",
            )
            for resource in code_resources:
                self.assertEqual(resource.stat().st_mode & 0o777, 0o644)
                self.assertEqual(resource.parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(sentinel.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (nested / "Contents/MacOS/Nested").stat().st_mode & 0o777,
                0o755,
            )
            self.assertEqual(
                (host / "Contents/MacOS/Host").stat().st_mode & 0o777,
                0o755,
            )

            nested_verify = subprocess.run(
                [CODESIGN, "--verify", "--strict", "--verbose=4", str(nested)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(nested_verify.returncode, 0, nested_verify.stderr)
            host_verify = subprocess.run(
                [
                    CODESIGN,
                    "--verify",
                    "--deep",
                    "--strict",
                    "--verbose=4",
                    str(host),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(host_verify.returncode, 0, host_verify.stderr)
            self.assertTrue(enumerate_bundle(host))

            code_resources[0].chmod(0o600)
            with self.assertRaisesRegex(
                CandidateError, "file mode must be 0644 or 0755"
            ):
                enumerate_bundle(host)

    def test_boundary_is_source_only_and_uses_one_fixed_codesign(self) -> None:
        source = BOUNDARY.read_text(encoding="utf-8")
        expected = """cfw_codesign_distribution_bundle() (
  umask 022
  exec /usr/bin/codesign "$@"
)"""
        self.assertEqual(source.count(expected), 1)
        self.assertEqual(source.count("/usr/bin/codesign"), 1)
        self.assertNotIn("eval", source)

        completed = subprocess.run(
            ["/bin/bash", "-p", str(BOUNDARY)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must be sourced", completed.stderr)


if __name__ == "__main__":
    unittest.main()
