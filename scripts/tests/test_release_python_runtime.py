from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts.publication import release_environment
from scripts.publication.bounded_process import BoundedProcessError
from scripts.publication.graph_model import load_pins
from scripts.release_python_runtime import require_closed_release_runtime


REPOSITORY = Path(__file__).resolve().parents[2]


def _swift_target_info(
    developer_dir: Path,
    deployment_target: str = "15.0",
) -> dict[str, object]:
    resource_root = (
        developer_dir / "Toolchains/XcodeDefault.xctoolchain/usr/lib/swift"
    )
    platform_root = resource_root / "macosx"
    return {
        "compilerVersion": (
            "Apple Swift version 6.3.3 "
            "(swiftlang-6.3.3.1.3 clang-2100.1.1.101)"
        ),
        "swiftCompilerTag": "swiftlang-6.3.3.1.3",
        "target": {
            "triple": f"arm64-apple-macosx{deployment_target}",
            "unversionedTriple": "arm64-apple-macosx",
            "moduleTriple": "arm64-apple-macos",
            "platform": "macosx",
            "arch": "arm64",
            "pointerWidthInBits": 64,
            "pointerWidthInBytes": 8,
            "swiftRuntimeCompatibilityVersion": "6.0",
            "compatibilityLibraries": [],
            "openbsdBTCFIEnabled": False,
            "librariesRequireRPath": True,
        },
        "paths": {
            "runtimeLibraryPaths": [str(platform_root), "/usr/lib/swift"],
            "runtimeLibraryImportPaths": [str(platform_root)],
            "runtimeResourcePath": str(resource_root),
        },
    }


class ReleaseEnvironmentBootstrapTests(unittest.TestCase):
    def test_first_process_receives_only_fixed_and_reviewed_inputs(self) -> None:
        source = {
            "PATH": "/tmp/untrusted-bin:/usr/bin:/bin",
            "HOME": "/tmp/untrusted-home",
            "BASH_ENV": "/tmp/untrusted-startup",
            "DYLD_INSERT_LIBRARIES": "/tmp/untrusted.dylib",
            "DYLD_LIBRARY_PATH": "/tmp/untrusted-library",
            "LD_PRELOAD": "/tmp/untrusted-preload.dylib",
            "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
            "CFW_BUILD_NUMBER": "40036",
            "CFW_UNSIGNED_VALIDATION_PYTHON": "/opt/release/bin/python3",
            "NOTARY_PROFILE": "release-profile",
        }

        bootstrap = release_environment._release_environment_bootstrap(source)

        self.assertEqual(
            bootstrap,
            {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
                "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
                "CFW_BUILD_NUMBER": "40036",
                "CFW_UNSIGNED_VALIDATION_PYTHON": "/opt/release/bin/python3",
                "NOTARY_PROFILE": "release-profile",
            },
        )

    def test_exported_shell_functions_are_rejected_before_bootstrap(self) -> None:
        with self.assertRaisesRegex(
            release_environment.PublicationError,
            "exported shell functions",
        ):
            release_environment._release_environment_bootstrap(
                {"BASH_FUNC_swift%%": "() { exit 0; }"}
            )

    def test_bash_execution_modes_are_rejected_before_bootstrap(self) -> None:
        for name in ("BASH_COMPAT", "POSIXLY_CORRECT"):
            with self.subTest(name=name), self.assertRaisesRegex(
                release_environment.PublicationError,
                "alternate Bash compatibility modes",
            ):
                release_environment._release_environment_bootstrap({name: "1"})


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

    def test_real_swift_identity_is_clean_repeatable_and_structured(self) -> None:
        first = release_environment.swift_toolchain_identity(
            REPOSITORY,
            self.baseline,
            self.pins["MACOS_DEPLOYMENT_TARGET"],
        )
        second = release_environment.swift_toolchain_identity(
            REPOSITORY,
            self.baseline,
            self.pins["MACOS_DEPLOYMENT_TARGET"],
        )

        self.assertEqual(first, second)
        self.assertRegex(first.version, r"^6[.][0-9]+[.][0-9]+$")
        document = json.loads(first.canonical)
        self.assertEqual(
            document["target"]["triple"],
            f"arm64-apple-macosx{self.pins['MACOS_DEPLOYMENT_TARGET']}",
        )
        self.assertNotIn(self.baseline["DEVELOPER_DIR"], first.canonical)

    def test_real_swift_identity_ignores_ambient_driver_selection(self) -> None:
        source = dict(os.environ)
        source.update(
            {
                "HOME": "/tmp/untrusted-swift-home",
                "PATH": "/tmp/untrusted-swift-bin:/usr/bin:/bin",
                "SDKROOT": "/tmp/untrusted-swift-sdk",
                "SWIFT_EXEC": "/tmp/untrusted-swift",
                "SWIFT_DRIVER_SWIFT_FRONTEND_EXEC": "/tmp/untrusted-frontend",
                "TOOLCHAINS": "untrusted",
            }
        )
        isolated = release_environment.release_tool_environment(
            REPOSITORY,
            self.pins,
            source,
            role=self.role,
        )

        observed = release_environment.swift_toolchain_identity(
            REPOSITORY,
            isolated,
            self.pins["MACOS_DEPLOYMENT_TARGET"],
        )
        expected = release_environment.swift_toolchain_identity(
            REPOSITORY,
            self.baseline,
            self.pins["MACOS_DEPLOYMENT_TARGET"],
        )
        self.assertEqual(observed, expected)
        self.assertNotEqual(isolated["HOME"], source["HOME"])
        self.assertNotEqual(isolated["PATH"], source["PATH"])
        for name in ("SDKROOT", "SWIFT_EXEC", "TOOLCHAINS"):
            self.assertNotIn(name, isolated)

    def test_swift_identity_normalizes_only_the_selected_xcode_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            developers = (
                root / "Xcode-A.app/Contents/Developer",
                root / "Xcode-B.app/Contents/Developer",
            )
            for developer in developers:
                developer.mkdir(parents=True)
            calls: list[list[str]] = []

            def run_target_info(argv, **kwargs):
                calls.append(list(argv))
                developer = Path(
                    kwargs["environment"]["DEVELOPER_DIR"]
                ).resolve(strict=True)
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps(_swift_target_info(developer)).encode("utf-8"),
                    b"",
                )

            identities = []
            with mock.patch.object(
                release_environment,
                "run_bounded_process",
                side_effect=run_target_info,
            ):
                for developer in developers:
                    identities.append(
                        release_environment.swift_toolchain_identity(
                            REPOSITORY,
                            {"DEVELOPER_DIR": str(developer)},
                            "15.0",
                        )
                    )

        self.assertEqual(identities[0], identities[1])
        self.assertEqual(
            calls,
            [
                [
                    "/usr/bin/swift",
                    "-print-target-info",
                    "-target",
                    "arm64-apple-macosx15.0",
                ]
            ]
            * 2,
        )

    def test_swift_identity_parser_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            developer = Path(temporary) / "Xcode.app/Contents/Developer"
            developer.mkdir(parents=True)
            base = _swift_target_info(developer)
            cases: dict[str, tuple[bytes, str]] = {}

            wrong_arch = json.loads(json.dumps(base))
            wrong_arch["target"]["arch"] = "x86_64"
            cases["wrong architecture"] = (
                json.dumps(wrong_arch).encode(),
                "differs from the release target",
            )
            extra_field = json.loads(json.dumps(base))
            extra_field["target"]["unexpected"] = True
            cases["unexpected field"] = (
                json.dumps(extra_field).encode(),
                "fields are malformed",
            )
            escaped_path = json.loads(json.dumps(base))
            escaped_path["paths"]["runtimeResourcePath"] = "/tmp/other/swift"
            cases["escaped path"] = (
                json.dumps(escaped_path).encode(),
                "escaped the selected Xcode",
            )
            mismatched_tag = json.loads(json.dumps(base))
            mismatched_tag["swiftCompilerTag"] = "swiftlang-6.3.3.1.4"
            cases["mismatched compiler tag"] = (
                json.dumps(mismatched_tag).encode(),
                "fields are malformed",
            )
            valid = json.dumps(base).encode()
            cases["duplicate field"] = (
                valid.replace(
                    b'{"compilerVersion":',
                    b'{"compilerVersion":"duplicate","compilerVersion":',
                    1,
                ),
                "not strict JSON",
            )
            cases["non-finite number"] = (
                valid.replace(b'"pointerWidthInBits": 64', b'"pointerWidthInBits": NaN'),
                "not strict JSON",
            )
            cases["non UTF-8"] = (b"\xff", "not strict JSON")
            cases["malformed JSON"] = (b"{", "not strict JSON")

            for label, (payload, message) in cases.items():
                completed = subprocess.CompletedProcess(
                    ["/usr/bin/swift"], 0, payload, b""
                )
                with self.subTest(label=label), mock.patch.object(
                    release_environment,
                    "run_bounded_process",
                    return_value=completed,
                ), self.assertRaisesRegex(
                    release_environment.PublicationError,
                    message,
                ):
                    release_environment.swift_toolchain_identity(
                        REPOSITORY,
                        {"DEVELOPER_DIR": str(developer)},
                        "15.0",
                    )

    def test_swift_identity_preserves_process_failure_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            developer = Path(temporary) / "Xcode.app/Contents/Developer"
            developer.mkdir(parents=True)
            payload = json.dumps(_swift_target_info(developer)).encode()
            completions = (
                (
                    subprocess.CompletedProcess(
                        ["/usr/bin/swift"], 0, payload, b"driver warning"
                    ),
                    "emitted diagnostics",
                ),
                (
                    subprocess.CompletedProcess(["/usr/bin/swift"], 42, b"", b"failed"),
                    "exit 42",
                ),
            )
            for completed, message in completions:
                with self.subTest(message=message), mock.patch.object(
                    release_environment,
                    "run_bounded_process",
                    return_value=completed,
                ), self.assertRaisesRegex(
                    release_environment.PublicationError,
                    message,
                ):
                    release_environment.swift_toolchain_identity(
                        REPOSITORY,
                        {"DEVELOPER_DIR": str(developer)},
                        "15.0",
                    )

            boundary = BoundedProcessError(
                "output-limit",
                "fixture output limit",
            )
            with mock.patch.object(
                release_environment,
                "run_bounded_process",
                side_effect=boundary,
            ), self.assertRaisesRegex(
                release_environment.PublicationError,
                "output exceeded its fixed bound",
            ):
                release_environment.swift_toolchain_identity(
                    REPOSITORY,
                    {"DEVELOPER_DIR": str(developer)},
                    "15.0",
                )

    def test_swift_identity_rejects_malformed_deployment_target(self) -> None:
        for deployment_target in ("", "15", "015.0", "15.0 -module-name injected"):
            with self.subTest(deployment_target=deployment_target), mock.patch.object(
                release_environment,
                "run_bounded_process",
            ) as runner:
                with self.assertRaisesRegex(
                    release_environment.PublicationError,
                    "deployment target is malformed",
                ):
                    release_environment.swift_toolchain_identity(
                        REPOSITORY,
                        self.baseline,
                        deployment_target,
                    )
                runner.assert_not_called()

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
