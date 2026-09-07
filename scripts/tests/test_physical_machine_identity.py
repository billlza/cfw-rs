from __future__ import annotations

import plistlib
import subprocess
import unittest

from scripts.harness.physical_machine_identity import (
    PhysicalMachineIdentityError,
    collect_boot_environment_sha256,
    collect_machine_identity,
    collect_machine_sha256,
    derive_machine_sha256,
    derive_boot_environment_sha256,
    self_check,
    validate_physical_hardware_model,
)


PLATFORM_UUID = "01234567-89AB-CDEF-0123-456789ABCDEF"


class PhysicalMachineIdentityTests(unittest.TestCase):
    def test_self_check(self) -> None:
        self_check()

    def test_derivation_is_case_canonical_and_domain_separated(self) -> None:
        upper = derive_machine_sha256(
            platform_uuid=PLATFORM_UUID,
            hardware_model="Mac16,1",
            architecture="arm64",
            virtualization_present=False,
        )
        lower = derive_machine_sha256(
            platform_uuid=PLATFORM_UUID.lower(),
            hardware_model="Mac16,1",
            architecture="arm64",
            virtualization_present=False,
        )
        self.assertEqual(upper, lower)
        self.assertEqual(
            upper,
            "e16dea85471fe6c16032fa874c25e3803d6142acedc805fb4ef04b2b190bb902",
        )

    def test_invalid_identity_components_fail_closed(self) -> None:
        cases = (
            ("not-a-uuid", "Mac16,1", "arm64", False, "UUID"),
            ("00000000-0000-0000-0000-000000000000", "Mac16,1", "arm64", False, "UUID"),
            (PLATFORM_UUID, "Mac 16,1", "arm64", False, "physical Apple"),
            (PLATFORM_UUID, "VirtualMac2,1", "arm64", False, "physical Apple"),
            (PLATFORM_UUID, "Mac16,1", "x86_64", False, "arm64"),
            (PLATFORM_UUID, "Mac16,1", "arm64", True, "virtualized"),
        )
        for platform_uuid, model, architecture, virtualized, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                PhysicalMachineIdentityError, message
            ):
                derive_machine_sha256(
                    platform_uuid=platform_uuid,
                    hardware_model=model,
                    architecture=architecture,
                    virtualization_present=virtualized,
                )

    def test_physical_model_allowlist_accepts_real_model_families(self) -> None:
        for model in (
            "Mac16,1",
            "MacBookAir10,1",
            "MacBookPro18,2",
            "Macmini9,1",
            "MacStudio1,1",
            "iMac21,1",
            "iMacPro1,1",
        ):
            with self.subTest(model=model):
                self.assertEqual(validate_physical_hardware_model(model), model)

    def test_virtual_and_unknown_model_families_are_rejected(self) -> None:
        for model in (
            "VirtualMac2,1",
            "VMware7,1",
            "Parallels17,1",
            "QEMU1,1",
            "Unknown1,1",
        ):
            with self.subTest(model=model), self.assertRaisesRegex(
                PhysicalMachineIdentityError, "physical Apple"
            ):
                validate_physical_hardware_model(model)

    def test_boot_environment_derivation_and_collection_are_canonical(self) -> None:
        volume_uuid = "11111111-2222-3333-4444-555555555555"
        group_uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        expected = derive_boot_environment_sha256(
            volume_uuid=volume_uuid,
            volume_group_uuid=group_uuid,
        )
        self.assertEqual(
            expected,
            "d474c92f7822316f5ebcf273cae689fdfa2c5348f9c2d73ff6dd8b24bb42cb63",
        )
        plist = plistlib.dumps(
            {
                "APFSVolumeGroupID": group_uuid,
                "Bootable": True,
                "FilesystemType": "apfs",
                "MountPoint": "/",
                "Sealed": "Yes",
                "SystemImage": False,
                "VolumeUUID": volume_uuid,
            }
        )

        def runner(command, **_kwargs):
            self.assertEqual(
                command, ["/usr/sbin/diskutil", "info", "-plist", "/"]
            )
            return subprocess.CompletedProcess(command, 0, plist, b"")

        self.assertEqual(collect_boot_environment_sha256(runner=runner), expected)

    def test_boot_environment_rejects_placeholder_or_unsealed_volume(self) -> None:
        for volume_uuid, sealed in (
            ("00000000-0000-0000-0000-000000000000", "Yes"),
            ("11111111-2222-3333-4444-555555555555", "No"),
        ):
            plist = plistlib.dumps(
                {
                    "APFSVolumeGroupID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "Bootable": True,
                    "FilesystemType": "apfs",
                    "MountPoint": "/",
                    "Sealed": sealed,
                    "SystemImage": False,
                    "VolumeUUID": volume_uuid,
                }
            )

            def runner(command, **_kwargs):
                return subprocess.CompletedProcess(command, 0, plist, b"")

            with self.subTest(volume_uuid=volume_uuid, sealed=sealed), self.assertRaises(
                PhysicalMachineIdentityError
            ):
                collect_boot_environment_sha256(runner=runner)

    def test_collection_uses_only_fixed_commands_and_outputs_one_digest(self) -> None:
        outputs = {
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
        }
        observed: list[tuple[str, ...]] = []

        def runner(command, **kwargs):
            key = tuple(command)
            observed.append(key)
            self.assertEqual(kwargs["input"], b"")
            self.assertEqual(kwargs["env"]["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
            return subprocess.CompletedProcess(command, 0, outputs[key], b"")

        digest = collect_machine_sha256(runner=runner)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(set(observed), set(outputs))

        identity = collect_machine_identity(runner=runner)
        self.assertEqual(identity.machine_sha256, digest)
        self.assertEqual(identity.hardware_model, "Mac16,1")
        self.assertEqual(identity.architecture, "arm64")

    def test_command_failure_or_stderr_is_not_ignored(self) -> None:
        for returncode, stderr in ((1, b"failed"), (0, b"warning")):
            with self.subTest(returncode=returncode, stderr=stderr):

                def runner(command, **_kwargs):
                    return subprocess.CompletedProcess(
                        command, returncode, b"Darwin\n", stderr
                    )

                with self.assertRaisesRegex(
                    PhysicalMachineIdentityError, "failed closed"
                ):
                    collect_machine_sha256(runner=runner)


if __name__ == "__main__":
    unittest.main()
