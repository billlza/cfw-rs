"""Exercise the resolved AEXML checkout check and the SwiftPM warning gate."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
CONTRACT = REPOSITORY / "scripts/xcodegen_dependency_contract.sh"

# What every XcodeGen bootstrap printed while the pinned AEXML 4.7.0 manifest
# still declared watchOS 4 (Xcode 27.0 and 27.1 alike).
UNPATCHED_AEXML_WARNING = (
    b"warning: 'aexml': /private/tmp/build/checkouts/AEXML/Package.swift:11:19: "
    b"warning: 'v4' is deprecated: watchOS 9.0 is the oldest supported version "
    b"[#DeprecatedDeclaration]\n"
)


def _run(script: str, *arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "/bin/bash", "-p", "-c",
            f'set -euo pipefail; source "$1"; shift; {script}',
            "xcodegen-contract-test", str(CONTRACT), *arguments,
        ],
        env=environment, capture_output=True, check=False,
    )


class ResolvedAexmlCheckoutTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.checkouts = self.root / "checkouts"
        self.checkout = self.checkouts / "AEXML"
        self.checkout.mkdir(parents=True)
        self.manifest = self.checkout / "Package.swift"
        self.reviewed = b"// fixture manifest\nlet watchOS = 9\n"
        self.manifest.write_bytes(self.reviewed)
        self._git("init", "--quiet")
        self._git("add", "Package.swift")
        self._git(
            "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "Fixture",
        )
        self.revision = self._git("rev-parse", "HEAD").stdout.decode().strip()
        self.environment = {
            **os.environ,
            "XCODEGEN_AEXML_COMMIT": self.revision,
            "XCODEGEN_AEXML_UPSTREAM_MANIFEST_SHA256": hashlib.sha256(self.reviewed).hexdigest(),
        }

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(self.checkout), *arguments],
            check=True, capture_output=True,
        )

    def _verify(self) -> subprocess.CompletedProcess[bytes]:
        return _run(
            'cfw_verify_xcodegen_aexml "$1"', str(self.checkouts),
            environment=self.environment,
        )

    def _assert_rejected(self, result: subprocess.CompletedProcess[bytes], reason: bytes) -> None:
        self.assertNotEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(reason, result.stderr)

    def test_the_pinned_pristine_checkout_is_accepted_and_left_untouched(self) -> None:
        result = self._verify()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        self.assertEqual(self.manifest.read_bytes(), self.reviewed)
        self.assertEqual(self._git("rev-parse", "HEAD").stdout.decode().strip(), self.revision)
        self.assertEqual(self._git("status", "--porcelain", "--untracked-files=all").stdout, b"")
        self.assertEqual(self._verify().returncode, 0)

    def test_another_revision_is_rejected(self) -> None:
        self.environment["XCODEGEN_AEXML_COMMIT"] = "0" * 40
        self._assert_rejected(self._verify(), b"pristine locked revision")

    def test_an_edited_manifest_is_rejected_and_kept(self) -> None:
        edited = b"// fixture manifest\nlet watchOS = 4\n"
        self.manifest.write_bytes(edited)
        self._assert_rejected(self._verify(), b"pristine locked revision")
        self.assertEqual(self.manifest.read_bytes(), edited)

    def test_untracked_checkout_content_is_rejected_and_kept(self) -> None:
        unrelated = self.checkout / "unrelated.swift"
        unrelated.write_bytes(b"unrelated content")
        self._assert_rejected(self._verify(), b"pristine locked revision")
        self.assertEqual(unrelated.read_bytes(), b"unrelated content")

    def test_a_manifest_other_than_the_reviewed_one_is_rejected(self) -> None:
        self.environment["XCODEGEN_AEXML_UPSTREAM_MANIFEST_SHA256"] = hashlib.sha256(
            b"// another manifest\n"
        ).hexdigest()
        self._assert_rejected(self._verify(), b"reviewed upstream manifest")

    def test_a_manifest_symlink_is_rejected(self) -> None:
        outside = self.root / "outside.swift"
        outside.write_bytes(self.reviewed)
        self.manifest.unlink()
        self.manifest.symlink_to(outside)
        self._assert_rejected(self._verify(), b"checkout or its manifest is unavailable")
        self.assertEqual(outside.read_bytes(), self.reviewed)

    def test_a_symlinked_checkout_is_rejected_even_when_its_target_is_genuine(self) -> None:
        genuine = self.root / "elsewhere"
        self.checkout.rename(genuine)
        for link, target, checkouts in (
            (self.checkout, genuine, self.checkouts),
            (self.root / "linked-checkouts", self.checkouts, self.root / "linked-checkouts"),
        ):
            with self.subTest(link=link.name):
                if link == self.checkout:
                    link.symlink_to(target)
                else:
                    self.checkout.unlink()
                    genuine.rename(self.checkout)
                    link.symlink_to(target)
                result = _run(
                    'cfw_verify_xcodegen_aexml "$1"', str(checkouts),
                    environment=self.environment,
                )
                self._assert_rejected(result, b"checkout or its manifest is unavailable")

    def test_a_missing_checkout_is_rejected(self) -> None:
        result = _run(
            'cfw_verify_xcodegen_aexml "$1"', str(self.root / "absent"),
            environment=self.environment,
        )
        self._assert_rejected(result, b"checkout or its manifest is unavailable")


class SwiftPMWarningGateTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.log = Path(temporary.name).resolve() / "swiftpm.log"

    def _gate(self, contents: bytes, phase: str = "dependency resolution") -> subprocess.CompletedProcess[bytes]:
        self.log.write_bytes(contents)
        return _run(
            'cfw_reject_swiftpm_warnings "$1" "$2"', str(self.log), phase,
            environment=dict(os.environ),
        )

    def test_a_clean_resolution_passes(self) -> None:
        result = self._gate(
            b"Fetching https://github.com/tadija/AEXML.git\n"
            b"Fetched https://github.com/tadija/AEXML.git from cache (0.41s)\n"
            b"Computing version for https://github.com/tadija/AEXML.git\n"
            b"Computed https://github.com/tadija/AEXML.git at 4.7.1 (0.62s)\n"
            b"Creating working copy for https://github.com/tadija/AEXML.git\n"
            b"Working copy of https://github.com/tadija/AEXML.git resolved at 4.7.1\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")

    def test_the_unpatched_aexml_manifest_warning_fails_resolution(self) -> None:
        result = self._gate(b"Fetching https://github.com/tadija/AEXML.git\n" + UNPATCHED_AEXML_WARNING)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"isolated XcodeGen dependency resolution emitted a warning", result.stderr)

    def test_a_build_warning_names_the_build(self) -> None:
        result = self._gate(b"Compiling XcodeGenKit\nwarning: unused variable 'x'\n", "build")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"isolated XcodeGen build emitted a warning", result.stderr)

    def test_every_warning_spelling_is_caught(self) -> None:
        for line in (
            b"warning: plain\n",
            b"Package.swift:3:1: warning: indented\n",
            b"\twarning\tafter a tab\n",
            b"WARNING: upper case\n",
        ):
            with self.subTest(line=line):
                result = self._gate(line)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"dependency resolution emitted a warning", result.stderr)

    def test_words_that_merely_contain_warning_pass(self) -> None:
        result = self._gate(
            b"swift-build -Xswiftc -warnings-as-errors\n"
            b"Build of product 'xcodegen' complete! (12.34s)\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_an_unreadable_log_is_an_error_not_a_pass(self) -> None:
        self.log.write_bytes(b"warning: hidden behind the file mode\n")
        self.log.chmod(0)
        self.addCleanup(self.log.chmod, 0o600)
        result = _run(
            'cfw_reject_swiftpm_warnings "$1" "$2"', str(self.log), "dependency resolution",
            environment=dict(os.environ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"isolated XcodeGen dependency resolution log could not be read", result.stderr)

    def test_a_missing_log_is_an_error(self) -> None:
        result = _run(
            'cfw_reject_swiftpm_warnings "$1" "$2"', str(self.log), "build",
            environment=dict(os.environ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"isolated XcodeGen build log is unavailable", result.stderr)


def _pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (REPOSITORY / "scripts/dependency_pins.env").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            pins[key] = value
    return pins


class PinnedAexmlReleaseTests(unittest.TestCase):
    def test_the_dependency_patch_resolves_aexml_at_the_pinned_revision(self) -> None:
        pins = _pins()
        patch = (REPOSITORY / pins["XCODEGEN_DEPENDENCY_PATCH_PATH"]).read_text(encoding="utf-8")
        self.assertIn(
            '       "location" : "https://github.com/tadija/AEXML.git",\n'
            '       "state" : {\n'
            '-        "revision" : "db806756c989760b35108146381535aec231092b",\n'
            '-        "version" : "4.7.0"\n'
            f'+        "revision" : "{pins["XCODEGEN_AEXML_COMMIT"]}",\n'
            '+        "version" : "4.7.1"\n',
            patch,
        )


if __name__ == "__main__":
    unittest.main()
