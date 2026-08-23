from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts.publication import release_environment
from scripts.publication.graph_model import load_pins
from scripts.release_python_runtime import require_closed_release_runtime


REPOSITORY = Path(__file__).resolve().parents[2]


class ReleaseEnvironmentRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pins = load_pins(REPOSITORY / "scripts/dependency_pins.env")
        source = dict(os.environ)
        cls.role = (
            "unsigned-validation"
            if "CFW_UNSIGNED_VALIDATION_PYTHON" in source
            else "production"
        )
        cls.baseline = release_environment.release_tool_environment(
            REPOSITORY,
            cls.pins,
            source,
            role=cls.role,
        )

    @staticmethod
    def encoded(environment: dict[str, str]) -> bytes:
        return b"".join(
            f"{name}={value}".encode("utf-8") + b"\0"
            for name, value in environment.items()
        )

    def call_with_output(self, output: bytes) -> dict[str, str]:
        completed = subprocess.CompletedProcess(
            args=["release-environment-fixture"],
            returncode=0,
            stdout=output,
            stderr=b"",
        )
        developer = Path(self.baseline["DEVELOPER_DIR"])

        def identity(argv, _repository, _label, _environment, maximum=512):
            del maximum
            if argv == [release_environment.APPLE_XCODEBUILD, "-version"]:
                return (
                    f"Xcode {self.pins['XCODE_VERSION']}; "
                    f"Build version {self.pins['XCODE_BUILD_VERSION']}"
                )
            if argv == [release_environment.APPLE_XCRUN, "--find", "swift"]:
                return str(
                    developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/swift"
                )
            if argv == [release_environment.APPLE_XCRUN, "--find", "xcodebuild"]:
                return str(developer / "usr/bin/xcodebuild")
            raise AssertionError(argv)

        with mock.patch.object(
            release_environment, "run_bounded_process", return_value=completed
        ), mock.patch.object(
            release_environment, "identity_output", side_effect=identity
        ):
            return release_environment.release_tool_environment(
                REPOSITORY,
                self.pins,
                role=self.role,
            )

    def test_identity_output_is_streaming_bounded(self) -> None:
        command = [
            "/bin/bash",
            "-p",
            "-c",
            "i=0; while (( i < 1000 )); do printf '0123456789'; (( i += 1 )); done",
        ]
        with self.assertRaisesRegex(
            release_environment.PublicationError,
            "output exceeded its fixed bound",
        ):
            release_environment.identity_output(
                command,
                REPOSITORY,
                "fixture",
                {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                maximum=256,
            )

    def test_identity_output_rejects_successful_diagnostics(self) -> None:
        with self.assertRaisesRegex(
            release_environment.PublicationError,
            "emitted diagnostics",
        ):
            release_environment.identity_output(
                [
                    "/bin/bash",
                    "-p",
                    "-c",
                    "printf 'fixture identity\\n'; printf 'warning\\n' >&2",
                ],
                REPOSITORY,
                "fixture",
                {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )

    def test_operational_values_round_trip_spaces_and_multiple_equals(self) -> None:
        environment = dict(self.baseline)
        for index, name in enumerate(
            sorted(release_environment._OPERATIONAL_ENVIRONMENT)
        ):
            if name == "CFW_UNSIGNED_VALIDATION_PYTHON":
                continue
            value = f"fixture {index}=alpha=beta gamma"
            if name == "CFW_TOOLCHAIN_ROOT":
                value = f"/private/tmp/{value}"
            environment[name] = value
        environment["NOTARY_PROFILE"] = "fixture = alpha=beta gamma"

        result = self.call_with_output(self.encoded(environment))

        for name in release_environment._OPERATIONAL_ENVIRONMENT:
            if name in environment:
                self.assertEqual(result[name], environment[name], name)
        self.assertEqual(result["NOTARY_PROFILE"], "fixture = alpha=beta gamma")
        self.assertNotIn("UNREVIEWED_ENVIRONMENT", result)

    def test_malformed_nul_environment_records_fail_closed(self) -> None:
        valid = self.encoded(self.baseline)
        cases = {
            "missing terminator": valid[:-1],
            "missing separator": valid + b"BROKEN\0",
            "duplicate": valid + f"PATH={self.baseline['PATH']}".encode() + b"\0",
            "non UTF-8": valid + b"BROKEN=\xff\0",
            "unknown": valid + b"UNREVIEWED_ENVIRONMENT=forbidden\0",
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    release_environment.PublicationError,
                    "malformed|diagnostics|closed contract",
                ):
                    self.call_with_output(payload)


class ReleaseRuntimeAdmissionTests(unittest.TestCase):
    def test_current_closed_runner_is_admitted(self) -> None:
        require_closed_release_runtime(allow_unsigned_validation=True)

    def test_unsigned_validation_is_not_production_admission(self) -> None:
        if "CFW_UNSIGNED_VALIDATION_PYTHON" in os.environ:
            with self.assertRaisesRegex(
                RuntimeError, "refuses unsigned-validation admission"
            ):
                require_closed_release_runtime()
        else:
            require_closed_release_runtime()

    def test_system_python_is_rejected(self) -> None:
        code = (
            "import sys; "
            f"sys.path.insert(0, {str(REPOSITORY / 'scripts')!r}); "
            "from release_python_runtime import require_closed_release_runtime; "
            "require_closed_release_runtime()"
        )
        environment = dict(os.environ)
        environment.pop("CFW_UNSIGNED_VALIDATION_PYTHON", None)
        completed = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-B", "-W", "error", "-c", code],
            cwd=REPOSITORY,
            env=environment,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"closed isolated launcher", completed.stderr)

    def test_production_wrapper_ignores_path_and_startup_poison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "poison-ran"
            fake_python = fake_bin / "python3"
            fake_python.write_text(
                f"#!/bin/bash\nprintf ran >'{marker}'\nexit 99\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            startup = root / "startup.sh"
            startup.write_text(f"printf ran >'{marker}'\n", encoding="utf-8")
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            environment["BASH_ENV"] = str(startup)
            environment["CFW_RELEASE_PYTHON_EXECUTABLE"] = str(fake_python)
            environment["HOME"] = str(root)
            validation_python = os.environ.get("CFW_UNSIGNED_VALIDATION_PYTHON")
            if validation_python:
                command = [
                    str(REPOSITORY / "scripts/run_release_ci_gate.sh"),
                    "--validation-python-executable",
                    validation_python,
                    "version-contract",
                ]
            else:
                command = [
                    str(REPOSITORY / "scripts/run_publication_evidence.sh"),
                    "--help",
                ]
            completed = subprocess.run(
                command,
                cwd=REPOSITORY,
                env=environment,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertFalse(marker.exists())
            if validation_python is None:
                self.assertIn(b"usage:", completed.stdout)

    def test_production_self_check_runs_in_the_current_closed_role(self) -> None:
        completed = subprocess.run(
            [
                "/bin/bash",
                "-p",
                "-c",
                'source "$1"; cfw_run_release_python_script "$2" '
                '"$2/scripts/production_release_evidence.py" self-check',
                "production-self-check-test",
                str(REPOSITORY / "scripts/release_python_launcher.sh"),
                str(REPOSITORY),
            ],
            cwd=REPOSITORY,
            env=dict(os.environ),
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertIn(b"orchestrator self-check passed", completed.stdout)


if __name__ == "__main__":
    unittest.main()
