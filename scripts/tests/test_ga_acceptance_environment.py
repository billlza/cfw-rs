from __future__ import annotations

import copy
import plistlib
import subprocess
import unittest

from scripts import ga_acceptance_environment as environment


PLATFORM_UUID = "01234567-89AB-CDEF-0123-456789ABCDEF"
VOLUME_UUID = "11111111-2222-3333-4444-555555555555"
VOLUME_GROUP_UUID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"


def command_outputs() -> dict[tuple[str, ...], bytes]:
    return {
        ("/usr/bin/uname", "-s"): b"Darwin\n",
        ("/usr/bin/uname", "-m"): b"arm64\n",
        ("/usr/sbin/sysctl", "-n", "hw.model"): b"Mac16,1\n",
        ("/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"): b"0\n",
        (
            "/usr/sbin/ioreg",
            "-a",
            "-r",
            "-l",
            "-d",
            "1",
            "-c",
            "IOPlatformExpertDevice",
        ): plistlib.dumps([{"IOPlatformUUID": PLATFORM_UUID}]),
        ("/usr/sbin/diskutil", "info", "-plist", "/"): plistlib.dumps(
            {
                "APFSVolumeGroupID": VOLUME_GROUP_UUID,
                "Bootable": True,
                "FilesystemType": "apfs",
                "MountPoint": "/",
                "Sealed": "Yes",
                "SystemImage": False,
                "VolumeUUID": VOLUME_UUID,
            }
        ),
        ("/usr/bin/sw_vers", "-buildVersion"): b"26A5388g\n",
        ("/usr/bin/sw_vers", "-productVersion"): b"27.0\n",
    }


class GAAcceptanceEnvironmentTests(unittest.TestCase):
    def test_observation_is_canonical_private_and_self_check_is_fixed(self) -> None:
        outputs = command_outputs()
        observed_commands: list[tuple[str, ...]] = []

        def runner(command, **kwargs):
            key = tuple(command)
            observed_commands.append(key)
            self.assertEqual(kwargs["input"], b"")
            self.assertEqual(kwargs["env"]["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
            return subprocess.CompletedProcess(command, 0, outputs[key], b"")

        observed = environment.observe_environment(runner=runner)
        environment.self_check()
        self.assertEqual(set(observed_commands), set(outputs))
        self.assertEqual(observed["architecture"], "arm64")
        self.assertEqual(observed["hardware_model"], "Mac16,1")
        self.assertEqual(observed["macos_product_version"], "27.0")
        self.assertEqual(observed["macos_build_version"], "26A5388g")
        digest = environment.environment_sha256(observed)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        encoded = environment.canonical_json(observed)
        self.assertNotIn(PLATFORM_UUID.lower().encode("ascii"), encoded.lower())
        self.assertNotIn(VOLUME_UUID.lower().encode("ascii"), encoded.lower())
        self.assertNotIn(VOLUME_GROUP_UUID.lower().encode("ascii"), encoded.lower())

    def test_machine_volume_and_macos_build_drift_fail_closed(self) -> None:
        baseline = environment.observe_environment(
            runner=lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 0, command_outputs()[tuple(command)], b""
            )
        )
        for field, replacement in (
            ("machine_sha256", "c" * 64),
            ("boot_environment_sha256", "d" * 64),
            ("macos_build_version", "26A5389a"),
        ):
            changed = copy.deepcopy(baseline)
            changed[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(
                environment.GAAcceptanceEnvironmentError, "changed"
            ):
                environment.require_same_environment(baseline, changed)

    def test_reboot_on_the_same_system_volume_is_not_a_document_field(self) -> None:
        observed = environment.observe_environment(
            runner=lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 0, command_outputs()[tuple(command)], b""
            )
        )
        self.assertNotIn("boot_session", observed)
        self.assertEqual(
            environment.require_same_environment(observed, copy.deepcopy(observed)),
            observed,
        )

    def test_unknown_fields_and_unsupported_platforms_are_rejected(self) -> None:
        observed = environment.observe_environment(
            runner=lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 0, command_outputs()[tuple(command)], b""
            )
        )
        cases = []
        extra = dict(observed)
        extra["io_platform_uuid"] = PLATFORM_UUID
        cases.append(extra)
        virtualized = dict(observed)
        virtualized["physical_nonvirtualized"] = False
        cases.append(virtualized)
        wrong_architecture = dict(observed)
        wrong_architecture["architecture"] = "x86_64"
        cases.append(wrong_architecture)
        boolean_schema = dict(observed)
        boolean_schema["schema_version"] = True
        cases.append(boolean_schema)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(
                environment.GAAcceptanceEnvironmentError
            ):
                environment.validate_environment(value)

    def test_command_failure_and_noncanonical_os_values_are_rejected(self) -> None:
        outputs = command_outputs()

        def failed(command, **_kwargs):
            if tuple(command) == ("/usr/bin/sw_vers", "-buildVersion"):
                return subprocess.CompletedProcess(command, 1, b"", b"failed")
            return subprocess.CompletedProcess(command, 0, outputs[tuple(command)], b"")

        with self.assertRaisesRegex(
            environment.GAAcceptanceEnvironmentError, "output is invalid"
        ):
            environment.observe_environment(runner=failed)

        def unavailable(_command, **_kwargs):
            raise OSError("fixture machine observation failure")

        with self.assertRaisesRegex(
            environment.GAAcceptanceEnvironmentError,
            "physical environment identity",
        ):
            environment.observe_environment(runner=unavailable)

        malformed = environment.observe_environment(
            runner=lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 0, outputs[tuple(command)], b""
            )
        )
        malformed["macos_product_version"] = "27"
        with self.assertRaisesRegex(
            environment.GAAcceptanceEnvironmentError, "product version"
        ):
            environment.validate_environment(malformed)


if __name__ == "__main__":
    unittest.main()
