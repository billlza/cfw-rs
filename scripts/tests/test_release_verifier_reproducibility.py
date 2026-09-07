from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import release_artifact_set
from scripts.publication.bounded_process import (
    BoundedProcessError,
    run_bounded_process,
)
from scripts.release_artifact_set import (
    RELEASE_VERIFIER_VENDOR_ROOT,
    _compiled_release_verifier,
)


REPOSITORY = Path(__file__).resolve().parents[2]
PUBLIC_KEY_ENVELOPE = (
    "untrusted comment: minisign public key E7620F1842B4E81F\n"
    "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
)
SIGNATURE_ENVELOPE = (
    "untrusted comment: signature from minisign secret key\n"
    "RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/"
    "z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n"
    "trusted comment: timestamp:1556193335\tfile:test\n"
    "y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1"
    "FkZZSNCisQbuQY+bHwhEBg=="
)


class ReleaseVerifierReproducibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        for variable in (
            "CFW_RELEASE_CARGO_INPUT_ROOT",
            "CFW_RELEASE_RUSTC_EXECUTABLE",
            "DEVELOPER_DIR",
        ):
            self.assertIn(
                variable,
                os.environ,
                f"release test environment omitted {variable}",
            )
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cfw-release-verifier-reproducibility."
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.short_parent = self.root / "a"
        self.long_parent = self.root / (
            "release-verifier-reproducibility-parent-with-a-"
            "deliberately-different-path-length"
        )
        for parent in (self.short_parent, self.long_parent):
            parent.mkdir(mode=0o700)

        self.fixture = self.root / "verification-fixture"
        self.fixture.mkdir(mode=0o700)
        self.configuration = self.fixture / "tauri.conf.json"
        self.archive = self.fixture / "test"
        self.signature = self.fixture / "test.sig"
        configuration = json.dumps(
            {
                "plugins": {
                    "updater": {
                        "pubkey": base64.b64encode(
                            PUBLIC_KEY_ENVELOPE.encode("utf-8")
                        ).decode("ascii")
                    }
                }
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.configuration.write_bytes(configuration)
        self.archive.write_bytes(b"test")
        self.signature.write_bytes(
            base64.b64encode(SIGNATURE_ENVELOPE.encode("utf-8")) + b"\n"
        )
        for path in (self.configuration, self.archive, self.signature):
            path.chmod(0o600)

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[bytes]:
        try:
            return run_bounded_process(
                command,
                cwd=REPOSITORY,
                environment={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                },
                timeout=300,
                output_limit=64 * 1024,
            )
        except BoundedProcessError as error:
            self.fail(
                "bounded release-verifier inspection failed: "
                f"{error.reason}"
            )

    def _build_and_inspect(self, parent: Path) -> dict[str, object]:
        with _compiled_release_verifier(
            REPOSITORY, temporary_parent=parent
        ) as build:
            executable = build.executable
            executable_bytes = executable.read_bytes()

            strict = self._run(
                [
                    "/usr/bin/codesign",
                    "--verify",
                    "--strict",
                    "--verbose=4",
                    str(executable),
                ]
            )
            self.assertEqual(strict.returncode, 0, strict.stderr.decode())

            signature_details = self._run(
                ["/usr/bin/codesign", "-d", "--verbose=4", str(executable)]
            )
            self.assertEqual(
                signature_details.returncode,
                0,
                signature_details.stderr.decode(),
            )
            details = signature_details.stderr.decode("utf-8")
            self.assertIn("Signature=adhoc", details)
            cdhashes = re.findall(r"^CDHash=([0-9a-f]+)$", details, re.MULTILINE)
            self.assertEqual(len(cdhashes), 1, details)

            uuid_result = self._run(
                ["/usr/bin/dwarfdump", "--uuid", str(executable)]
            )
            self.assertEqual(
                uuid_result.returncode, 0, uuid_result.stderr.decode()
            )
            uuids = re.findall(
                rb"^UUID: ([0-9A-F-]+) \(arm64\) ",
                uuid_result.stdout,
                re.MULTILINE,
            )
            self.assertEqual(len(uuids), 1, uuid_result.stdout.decode())

            verification = self._run(
                [
                    str(executable),
                    str(self.configuration),
                    str(self.archive),
                    str(self.signature),
                    "--json",
                ]
            )
            self.assertEqual(
                verification.returncode, 0, verification.stderr.decode()
            )
            self.assertEqual(verification.stderr, b"")
            receipt = json.loads(verification.stdout.decode("utf-8"))

            return {
                "apple_toolchain": build.apple_toolchain,
                "bytes": executable_bytes,
                "private_build_root": str(executable.parents[3]),
                "cargo_lock_sha256": build.cargo_lock_sha256,
                "cargo_vendor_sha256": build.cargo_vendor_sha256,
                "cdhash": cdhashes[0],
                "dependency_sources": build.dependency_sources,
                "executable_sha256": hashlib.sha256(executable_bytes).hexdigest(),
                "isolated_lock_sha256": build.isolated_lock_sha256,
                "receipt": receipt,
                "receipt_stdout": verification.stdout,
                "rust_toolchain_surface": build.toolchain_surface,
                "size": len(executable_bytes),
                "toolchain": build.toolchain,
                "uuid": uuids[0].decode("ascii"),
            }

    def test_clean_builds_from_different_root_lengths_are_byte_identical(
        self,
    ) -> None:
        self.assertGreater(
            abs(len(str(self.long_parent)) - len(str(self.short_parent))),
            32,
        )

        build_calls: list[tuple[list[str], dict[str, str]]] = []
        real_runner = release_artifact_set._run_bounded_process

        def record_build(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            if kwargs.get("label") == "release verifier build":
                environment = kwargs.get("environment")
                self.assertIsInstance(environment, dict)
                build_calls.append((list(command), dict(environment)))
            return real_runner(command, **kwargs)

        with patch.object(
            release_artifact_set,
            "_run_bounded_process",
            side_effect=record_build,
        ):
            first = self._build_and_inspect(self.short_parent)
            self.assertEqual(list(self.short_parent.iterdir()), [])
            second = self._build_and_inspect(self.long_parent)
            self.assertEqual(list(self.long_parent.iterdir()), [])

        self.assertEqual(len(build_calls), 2)
        build_roots: list[Path] = []
        for (command, environment), parent in zip(
            build_calls,
            (self.short_parent, self.long_parent),
            strict=True,
        ):
            self.assertIn("--target-dir", command)
            target = Path(command[command.index("--target-dir") + 1])
            temporary = Path(environment["TMPDIR"])
            cargo_home = Path(environment["CARGO_HOME"])
            for path in (target, temporary, cargo_home):
                self.assertTrue(path.is_relative_to(parent))
            build_roots.append(target.parent)
        self.assertNotEqual(build_roots[0], build_roots[1])
        self.assertNotEqual(
            build_calls[0][1]["TMPDIR"], build_calls[1][1]["TMPDIR"]
        )
        self.assertNotEqual(
            build_calls[0][1]["CARGO_HOME"], build_calls[1][1]["CARGO_HOME"]
        )

        first_bytes = first.pop("bytes")
        second_bytes = second.pop("bytes")
        first_build_root = Path(first.pop("private_build_root"))
        second_build_root = Path(second.pop("private_build_root"))
        self.assertEqual(first_build_root, build_roots[0])
        self.assertEqual(second_build_root, build_roots[1])
        self.assertNotEqual(first_build_root, second_build_root)
        self.assertEqual(first_build_root.parent, self.short_parent)
        self.assertEqual(second_build_root.parent, self.long_parent)
        self.assertTrue(
            first_bytes == second_bytes,
            "release verifier executable digest drifted: "
            f"{hashlib.sha256(first_bytes).hexdigest()} != "
            f"{hashlib.sha256(second_bytes).hexdigest()}",
        )
        self.assertEqual(first, second)
        self.assertGreater(first["size"], 0)
        self.assertRegex(first["executable_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(
            first["uuid"],
            r"^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$",
        )
        self.assertRegex(first["cdhash"], r"^[0-9a-f]{40}$")

        expected_receipt = {
            "archive_filename": "test",
            "archive_sha256": hashlib.sha256(b"test").hexdigest(),
            "archive_size": 4,
            "document": "cfw-updater-embedded-pubkey-verification-v1",
            "embedded_public_key_sha256": hashlib.sha256(
                PUBLIC_KEY_ENVELOPE.encode("utf-8")
            ).hexdigest(),
            "result": "verified",
            "schema_version": 1,
            "signature_filename": "test.sig",
            "signature_sha256": hashlib.sha256(
                self.signature.read_bytes()
            ).hexdigest(),
            "signature_size": self.signature.stat().st_size,
            "tauri_config_sha256": hashlib.sha256(
                self.configuration.read_bytes()
            ).hexdigest(),
        }
        self.assertEqual(first["receipt"], expected_receipt)
        self.assertEqual(
            first["receipt_stdout"],
            (
                json.dumps(
                    expected_receipt,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )

        executable_bytes = first_bytes
        self.assertTrue(
            RELEASE_VERIFIER_VENDOR_ROOT.encode() in executable_bytes,
            f"stable vendor prefix absent from {first['executable_sha256']}",
        )
        forbidden_paths = (
            ("short temporary parent", str(self.short_parent)),
            ("long temporary parent", str(self.long_parent)),
            ("Cargo input root", os.environ["CFW_RELEASE_CARGO_INPUT_ROOT"]),
            ("home directory", str(Path.home())),
            ("developer directory", os.environ["DEVELOPER_DIR"]),
            ("macOS user root", "/Users/"),
            ("macOS temporary root", "/private/tmp/"),
        )
        for label, forbidden in forbidden_paths:
            with self.subTest(label=label):
                self.assertTrue(
                    forbidden.encode() not in executable_bytes,
                    "forbidden path category present in "
                    f"{first['executable_sha256']}: {label}",
                )


if __name__ == "__main__":
    unittest.main()
