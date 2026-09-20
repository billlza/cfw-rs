from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.verify_candidate_bundle import (
    CandidateError,
    enumerate_bundle,
    verify_macho,
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
            "#!/bin/sh\n"
            "printf '[cargo-home=%s]\\n[offline=%s]\\n' \"$CARGO_HOME\" \"$CARGO_NET_OFFLINE\"\n"
            "printf '[%s]\\n' \"$@\"\n",
            encoding="utf-8",
        )
        self.tauri.chmod(0o755)
        self.cargo_home = self.root / "cargo-home"
        self.cargo_home.mkdir(mode=0o700)
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
        environment_updates: dict[str, str | None] | None = None,
        errexit: bool = True,
        readonly_caller_tauri: Path | None = None,
        runtime_verifier_failure_call: int | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = dict(os.environ)
        for variable in SIGNING_VARIABLES:
            environment.pop(variable, None)
        environment.update(
            {
                "CARGO_HOME": str(self.cargo_home),
                "CARGO_NET_OFFLINE": "true",
                "CFW_RELEASE_PYTHON_EXECUTABLE": sys.executable,
            }
        )
        if environment_updates:
            for variable, value in environment_updates.items():
                if value is None:
                    environment.pop(variable, None)
                else:
                    environment[variable] = value
        shell = ("set -euo pipefail; " if errexit else "set -uo pipefail; ")
        shell += 'source "$1"; '
        shell += (
            'contract_test_repository="$5"; '
            'contract_test_cargo_home="$6"; '
            'contract_test_runtime_failure_call="$8"; '
            "contract_test_runtime_verification_count=0; "
            "cfw_verify_release_cargo_runtime() { "
            "contract_test_runtime_verification_count="
            "$((contract_test_runtime_verification_count + 1)); "
            'if [[ "$#" -ne 2 || "$1" != "$contract_test_repository" || '
            '"$2" != "$contract_test_cargo_home" ]]; then '
            "echo 'fixture error: unexpected Cargo runtime verification arguments' >&2; "
            "return 97; "
            "fi; "
            'if [[ "$contract_test_runtime_failure_call" -ne 0 && '
            '"$contract_test_runtime_verification_count" -eq '
            '"$contract_test_runtime_failure_call" ]]; then '
            "echo 'fixture error: Cargo runtime verification rejected' >&2; "
            "return 86; "
            "fi; "
            "}; "
        )
        if readonly_caller_tauri is not None:
            shell += (
                'readonly app_dir="$2"; '
                'readonly tauri_bin="$7"; '
                'readonly config_override="$4"; '
                'readonly variable="caller-variable"; '
            )
        shell += (
            'cfw_build_tauri_host_skeleton "$2" "$3" "$4"; '
            "contract_test_status=$?; "
            'if [[ "$contract_test_status" -eq 0 && '
            '"$contract_test_runtime_verification_count" -ne 2 ]]; then '
            "echo 'fixture error: Cargo runtime verifier was not called twice' >&2; "
            "exit 96; "
            "fi; "
            'exit "$contract_test_status"'
        )
        command = [
            "/bin/bash",
            "-p",
            "-c",
            shell,
            "tauri-host-skeleton-test",
            str(CONTRACT),
            str(self.app_dir),
            str(self.tauri),
            self.override if override is None else override,
            str(REPOSITORY),
            str(self.cargo_home),
            str(readonly_caller_tauri) if readonly_caller_tauri else "",
            str(runtime_verifier_failure_call or 0),
        ]
        return subprocess.run(
            command,
            check=False,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_candidate_verifier_rejects_non_distribution_macho_mode(self) -> None:
        binary = self.root / "host-binary"
        binary.write_bytes(b"fixture")
        binary.chmod(0o700)

        with self.assertRaisesRegex(CandidateError, "mode must be 0755"):
            verify_macho(binary)

    def test_candidate_verifier_rejects_non_distribution_bundle_modes(self) -> None:
        bundle = self.root / "Bundle.app"
        bundle.mkdir()
        bundle.chmod(0o755)
        resource = bundle / "resource.txt"
        resource.write_bytes(b"fixture")
        resource.chmod(0o600)
        with self.assertRaisesRegex(CandidateError, "file mode must be 0644 or 0755"):
            enumerate_bundle(bundle)

        resource.chmod(0o644)
        nested = bundle / "Contents"
        nested.mkdir()
        nested.chmod(0o700)
        with self.assertRaisesRegex(CandidateError, "directory mode must be 0755"):
            enumerate_bundle(bundle)

    def test_runner_invokes_tauri_without_no_sign(self) -> None:
        completed = self.run_contract()
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        arguments = completed.stdout.decode()
        self.assertIn(f"[cargo-home={self.cargo_home}]\n", arguments)
        self.assertIn("[offline=true]\n", arguments)
        self.assertIn(
            "[build]\n[--bundles]\n[app]\n[--ci]\n"
            "[--features]\n[physical-release-evidence]\n[--config]\n",
            arguments,
        )
        self.assertNotIn("--no-sign", arguments)

    def test_runner_isolated_from_readonly_caller_variables_without_errexit(self) -> None:
        caller_tauri = self.root / "caller-tauri"
        caller_tauri.write_text(
            "#!/bin/sh\nprintf '[caller-tauri]\\n'\n",
            encoding="utf-8",
        )
        caller_tauri.chmod(0o755)

        completed = self.run_contract(
            errexit=False,
            readonly_caller_tauri=caller_tauri,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        expected_arguments = (
            f"[cargo-home={self.cargo_home}]\n"
            "[offline=true]\n"
            "[build]\n"
            "[--bundles]\n"
            "[app]\n"
            "[--ci]\n"
            "[--features]\n"
            "[physical-release-evidence]\n"
            "[--config]\n"
            f"[{self.override}]\n"
        )
        self.assertEqual(completed.stdout.decode(), expected_arguments)
        self.assertNotIn(b"caller-tauri", completed.stdout)

    def test_runner_requires_an_offline_absolute_cargo_runtime(self) -> None:
        for environment_updates in (
            {"CARGO_HOME": None},
            {"CARGO_HOME": "relative-cargo-home"},
            {"CARGO_NET_OFFLINE": None},
            {"CARGO_NET_OFFLINE": "false"},
        ):
            with self.subTest(environment_updates=environment_updates):
                completed = self.run_contract(
                    environment_updates=environment_updates
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"verified candidate Cargo runtime", completed.stderr)
                self.assertNotIn(b"[build]", completed.stdout)

    def test_runtime_verification_failure_blocks_before_and_after_tauri(self) -> None:
        before = self.run_contract(
            errexit=False,
            runtime_verifier_failure_call=1,
        )
        self.assertNotEqual(before.returncode, 0)
        self.assertIn(b"Cargo runtime verification rejected", before.stderr)
        self.assertNotIn(b"[build]", before.stdout)

        after = self.run_contract(runtime_verifier_failure_call=2)
        self.assertNotEqual(after.returncode, 0)
        self.assertIn(b"Cargo runtime verification rejected", after.stderr)
        self.assertIn(b"[build]", after.stdout)

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
