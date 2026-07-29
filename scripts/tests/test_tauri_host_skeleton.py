from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.verify_candidate_bundle import (
    CandidateError,
    verify_unsigned_host_skeleton,
)


REPOSITORY = Path(__file__).resolve().parents[2]
CONTRACT = REPOSITORY / "scripts/tauri_host_skeleton.sh"
SIGNING_VARIABLES = (
    "APPLE_CERTIFICATE",
    "APPLE_CERTIFICATE_PASSWORD",
    "APPLE_SIGNING_IDENTITY",
)


class TauriHostSkeletonRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.app_dir = self.root / "app"
        self.app_dir.mkdir()
        self.config_path = self.app_dir / "tauri.conf.json"
        self.write_config({"bundle": {"macOS": {}}})
        self.tauri = self.root / "cargo-tauri"
        self.tauri.write_text(
            "#!/bin/sh\nprintf '[%s]\\n' \"$@\"\n",
            encoding="utf-8",
        )
        self.tauri.chmod(0o755)
        self.override = json.dumps(
            {"bundle": {"macOS": {"bundleVersion": "40000"}}},
            separators=(",", ":"),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, value: object) -> None:
        self.config_path.write_text(json.dumps(value), encoding="utf-8")

    def run_contract(
        self,
        *,
        override: str | None = None,
        environment_updates: dict[str, str] | None = None,
        errexit: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = dict(os.environ)
        for variable in SIGNING_VARIABLES:
            environment.pop(variable, None)
        if environment_updates:
            environment.update(environment_updates)
        shell = (
            ("set -euo pipefail; " if errexit else "set -uo pipefail; ")
            + 'source "$1"; '
            'cfw_build_tauri_host_skeleton "$2" "$3" "$4"'
        )
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                shell,
                "tauri-host-skeleton-test",
                str(CONTRACT),
                str(self.app_dir),
                str(self.tauri),
                self.override if override is None else override,
            ],
            check=False,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_runner_invokes_tauri_without_no_sign(self) -> None:
        completed = self.run_contract()
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        arguments = completed.stdout.decode()
        self.assertIn("[build]\n[--bundles]\n[app]\n[--ci]\n[--config]\n", arguments)
        self.assertNotIn("--no-sign", arguments)

    def test_runner_rejects_every_signing_environment_variable_even_when_empty(self) -> None:
        for variable in SIGNING_VARIABLES:
            for value in ("", "injected"):
                with self.subTest(variable=variable, value=value):
                    completed = self.run_contract(
                        environment_updates={variable: value}
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(variable.encode(), completed.stderr)
                    self.assertNotIn(b"[build]", completed.stdout)

    def test_runner_rejects_signing_identity_in_base_or_override(self) -> None:
        for value in (None, "", "-", "Developer ID Application: example"):
            with self.subTest(location="base", value=value):
                self.write_config(
                    {"bundle": {"macOS": {"signingIdentity": value}}}
                )
                completed = self.run_contract()
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"signingIdentity", completed.stderr)
        self.write_config({"bundle": {"macOS": {}}})
        for value in (None, "", "-", "Developer ID Application: example"):
            with self.subTest(location="override", value=value):
                override = json.dumps(
                    {"bundle": {"macOS": {"signingIdentity": value}}}
                )
                completed = self.run_contract(override=override)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"signingIdentity", completed.stderr)

    def test_preflight_failure_cannot_execute_tauri_without_errexit(self) -> None:
        override = json.dumps(
            {"bundle": {"macOS": {"signingIdentity": "-"}}}
        )
        completed = self.run_contract(override=override, errexit=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"signingIdentity", completed.stderr)
        self.assertNotIn(b"[build]", completed.stdout)

    def test_runner_rejects_every_automatic_platform_configuration(self) -> None:
        for name in (
            "tauri.macos.conf.json",
            "tauri.macos.conf.json5",
            "Tauri.macos.toml",
        ):
            with self.subTest(name=name):
                path = self.app_dir / name
                path.write_text("{}", encoding="utf-8")
                completed = self.run_contract()
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(name.encode(), completed.stderr)
                path.unlink()

    def test_runner_rejects_duplicate_keys_in_base_and_override(self) -> None:
        self.config_path.write_text(
            '{"bundle":{"macOS":{}},"bundle":{"macOS":{}}}',
            encoding="utf-8",
        )
        completed = self.run_contract()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"duplicate JSON key", completed.stderr)

        self.write_config({"bundle": {"macOS": {}}})
        completed = self.run_contract(
            override='{"bundle":{"macOS":{},"macOS":{}}}'
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"duplicate JSON key", completed.stderr)

    def test_runner_rejects_a_symlinked_or_hard_linked_base_config(self) -> None:
        hard_link = self.root / "hard-linked-config.json"
        os.link(self.config_path, hard_link)
        completed = self.run_contract()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"regular non-linked file", completed.stderr)
        hard_link.unlink()

        real_config = self.root / "real-config.json"
        self.config_path.replace(real_config)
        self.config_path.symlink_to(real_config)
        completed = self.run_contract()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"regular non-linked file", completed.stderr)


class UnsignedHostArtifactTests(unittest.TestCase):
    VALID_DETAILS = "\n".join(
        (
            "Executable=/tmp/Clash for Mac.app/Contents/MacOS/clash-for-mac",
            "Identifier=clash_for_mac-test",
            "Format=app bundle with Mach-O thin (arm64)",
            "CodeDirectory v=20400 size=100 flags=0x20002(adhoc,linker-signed) hashes=1+0 location=embedded",
            "Signature=adhoc",
            "Info.plist=not bound",
            "TeamIdentifier=not set",
            "Sealed Resources=none",
        )
    )
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.app = Path(self.temporary.name) / "Clash for Mac.app"
        (self.app / "Contents").mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def results(
        self,
        *,
        details: str | None = None,
        entitlements: str = "",
        linker_returncode: int = 0,
        linker_error: str = "",
        verify_returncode: int = 1,
        verify_error: str | None = None,
    ) -> list[subprocess.CompletedProcess[str]]:
        return [
            subprocess.CompletedProcess(
                ["codesign", "display"],
                0,
                "",
                self.VALID_DETAILS if details is None else details,
            ),
            subprocess.CompletedProcess(
                ["codesign", "entitlements"], 0, entitlements, "Executable=test\n"
            ),
            subprocess.CompletedProcess(
                ["codesign", "linker-verify"],
                linker_returncode,
                "",
                linker_error,
            ),
            subprocess.CompletedProcess(
                ["codesign", "resource-verify"],
                verify_returncode,
                "",
                (
                    f"{self.app}: code has no resources but signature indicates they must be present"
                    if verify_error is None
                    else verify_error
                ),
            ),
        ]

    def test_accepts_only_the_unsealed_linker_signature(self) -> None:
        nested_signature = (
            self.app
            / "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/_CodeSignature"
        )
        nested_signature.mkdir(parents=True)
        (nested_signature / "CodeResources").write_bytes(b"signed nested product")
        with mock.patch(
            "scripts.verify_candidate_bundle.subprocess.run",
            side_effect=self.results(),
        ) as run:
            verify_unsigned_host_skeleton(self.app)
        self.assertEqual(run.call_count, 4)
        self.assertEqual(
            [invocation.args[0] for invocation in run.call_args_list],
            [
                ["/usr/bin/codesign", "-d", "--verbose=4", str(self.app)],
                [
                    "/usr/bin/codesign",
                    "-d",
                    "--entitlements",
                    "-",
                    "--xml",
                    str(self.app),
                ],
                [
                    "/usr/bin/codesign",
                    "--verify",
                    "--strict",
                    "--ignore-resources",
                    str(self.app),
                ],
                ["/usr/bin/codesign", "--verify", "--strict", str(self.app)],
            ],
        )
        for invocation in run.call_args_list:
            self.assertEqual(invocation.kwargs["env"]["LANG"], "C")
            self.assertEqual(invocation.kwargs["env"]["LC_ALL"], "C")

    def test_rejects_an_outer_code_resource_seal_including_a_symlink(self) -> None:
        signature = self.app / "Contents/_CodeSignature"
        signature.symlink_to(self.app / "missing")
        with self.assertRaisesRegex(CandidateError, "code-resource seal"):
            verify_unsigned_host_skeleton(self.app)

    def test_rejects_non_linker_or_distribution_signature_metadata(self) -> None:
        mutations = (
            self.VALID_DETAILS.replace(
                "flags=0x20002(adhoc,linker-signed)", "flags=0x2(adhoc)"
            ),
            self.VALID_DETAILS + "\nAuthority=Developer ID Application: example",
            self.VALID_DETAILS + "\nwarning: codesign display drift",
            self.VALID_DETAILS.replace("TeamIdentifier=not set", "TeamIdentifier=TEAM"),
        )
        for details in mutations:
            with self.subTest(details=details.splitlines()[-1]):
                with mock.patch(
                    "scripts.verify_candidate_bundle.subprocess.run",
                    side_effect=self.results(details=details),
                ):
                    with self.assertRaises(CandidateError):
                        verify_unsigned_host_skeleton(self.app)

    def test_rejects_entitlements_or_an_unexpected_codesign_verify_result(self) -> None:
        cases = (
            self.results(entitlements="<plist><dict/></plist>"),
            self.results(linker_returncode=1, linker_error="invalid CodeDirectory"),
            self.results(linker_error="warning: unexpected diagnostic"),
            self.results(verify_returncode=0),
            self.results(verify_error="warning: unexpected diagnostic"),
            self.results(verify_error="resource envelope is malformed"),
        )
        for results in cases:
            with self.subTest(result=results[-1]):
                with mock.patch(
                    "scripts.verify_candidate_bundle.subprocess.run",
                    side_effect=results,
                ):
                    with self.assertRaises(CandidateError):
                        verify_unsigned_host_skeleton(self.app)


if __name__ == "__main__":
    unittest.main()
