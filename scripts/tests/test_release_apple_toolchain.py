from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.release_apple_toolchain import (
    APPLE_TOOLCHAIN_DOCUMENT,
    APPLE_TOOLCHAIN_SCHEMA_VERSION,
    DEVELOPER_DIRECTORY_PLACEHOLDER,
    ReleaseAppleToolchainError,
    _trusted_directory,
    capture_release_apple_toolchain,
    validate_recorded_release_apple_toolchain,
)


REPOSITORY = Path(__file__).resolve().parents[2]


def selected_developer_directory() -> Path:
    selected = os.environ.get("DEVELOPER_DIR")
    if selected is None:
        completed = subprocess.run(
            ["/usr/bin/xcode-select", "-p"],
            cwd=REPOSITORY,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            },
            check=True,
            capture_output=True,
        )
        selected = completed.stdout.decode("utf-8").strip()
    return Path(selected).resolve(strict=True)


class ReleaseAppleToolchainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.developer_directory = selected_developer_directory()
        cls.environment = {
            "DEVELOPER_DIR": str(cls.developer_directory),
        }
        cls.observed = capture_release_apple_toolchain(
            REPOSITORY, cls.environment
        )

    def test_selected_xcode_linker_surface_is_path_independent_and_pinned(
        self,
    ) -> None:
        binding = self.observed.binding

        self.assertEqual(binding["document"], APPLE_TOOLCHAIN_DOCUMENT)
        self.assertEqual(
            binding["schema_version"], APPLE_TOOLCHAIN_SCHEMA_VERSION
        )
        self.assertEqual(
            binding["developer_directory"],
            DEVELOPER_DIRECTORY_PLACEHOLDER,
        )
        self.assertEqual(binding["deployment_target"], "15.0")
        self.assertEqual(binding["xcode_version"], "26.6")
        self.assertEqual(binding["xcode_build_version"], "17F113")
        self.assertEqual(
            binding["clang"]["path"],
            str(self.observed.clang.relative_to(self.developer_directory)),
        )
        self.assertEqual(
            binding["ld"]["path"],
            str(self.observed.linker.relative_to(self.developer_directory)),
        )
        self.assertNotIn(
            str(self.developer_directory),
            json.dumps(binding, sort_keys=True),
        )
        self.assertEqual(
            validate_recorded_release_apple_toolchain(
                binding, REPOSITORY, self.environment
            ),
            binding,
        )

    def test_official_versioned_sdk_alias_is_bound_to_its_real_target(self) -> None:
        sdk = self.observed.binding["sdk"]
        self.assertEqual(sdk["version"], "26.5")
        self.assertEqual(
            sdk["selected_path"],
            "Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.5.sdk",
        )
        self.assertEqual(
            sdk["resolved_path"],
            "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
        )
        self.assertTrue(self.observed.sdk_root.is_symlink())

    def test_deployment_target_comes_from_pins_and_rejects_ambient_drift(self) -> None:
        self.assertEqual(self.observed.deployment_target, "15.0")
        drifted = {
            **self.environment,
            "MACOSX_DEPLOYMENT_TARGET": "14.0",
        }
        with self.assertRaisesRegex(
            ReleaseAppleToolchainError, "differs from its pins"
        ):
            capture_release_apple_toolchain(REPOSITORY, drifted)

    def test_relative_or_user_owned_developer_directory_is_rejected(self) -> None:
        with self.assertRaisesRegex(ReleaseAppleToolchainError, "not absolute"):
            capture_release_apple_toolchain(
                REPOSITORY, {"DEVELOPER_DIR": "relative/Xcode/Developer"}
            )

        with tempfile.TemporaryDirectory() as temporary:
            user_owned = Path(temporary).resolve()
            with self.assertRaisesRegex(
                ReleaseAppleToolchainError, "trusted real directory"
            ):
                _trusted_directory(
                    user_owned,
                    "user-owned Xcode fixture",
                )

    def test_recorded_tool_digest_drift_fails_closed(self) -> None:
        drifted = deepcopy(self.observed.binding)
        drifted["ld"]["sha256"] = "0" * 64

        with self.assertRaisesRegex(
            ReleaseAppleToolchainError,
            "differ from the selected toolchain",
        ):
            validate_recorded_release_apple_toolchain(
                drifted, REPOSITORY, self.environment
            )

    def test_json_type_equivalents_cannot_bypass_nested_binding_types(self) -> None:
        mutations = {
            "boolean-schema": lambda binding: binding.__setitem__(
                "schema_version", True
            ),
            "floating-size": lambda binding: binding["ld"].__setitem__(
                "size", float(binding["ld"]["size"])
            ),
        }

        for name, mutate in mutations.items():
            with self.subTest(name=name):
                drifted = deepcopy(self.observed.binding)
                mutate(drifted)
                with self.assertRaises(ReleaseAppleToolchainError):
                    validate_recorded_release_apple_toolchain(
                        drifted, REPOSITORY, self.environment
                    )


if __name__ == "__main__":
    unittest.main()
