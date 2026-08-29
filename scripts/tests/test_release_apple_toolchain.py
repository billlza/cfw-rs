from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts.release_apple_toolchain import (
    APPLE_TOOLCHAIN_DOCUMENT,
    APPLE_TOOLCHAIN_SCHEMA_VERSION,
    DEVELOPER_DIRECTORY_PLACEHOLDER,
    MAX_CLANG_TOOL_BYTES,
    MAX_LINKER_TOOL_BYTES,
    ReleaseAppleToolchainError,
    _file_record,
    _trusted_directory,
    _validate_apple_toolchain_binding_shape,
    _validate_file_binding,
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

    def test_clang_and_linker_have_distinct_fixed_size_limits(self) -> None:
        self.assertEqual(MAX_CLANG_TOOL_BYTES, 512 * 1024 * 1024)
        self.assertEqual(MAX_LINKER_TOOL_BYTES, 32 * 1024 * 1024)
        for label, maximum in (
            ("recorded clang", MAX_CLANG_TOOL_BYTES),
            ("recorded linker", MAX_LINKER_TOOL_BYTES),
        ):
            with self.subTest(label=label, boundary="maximum"):
                binding = {
                    "path": "Toolchains/tool",
                    "sha256": "a" * 64,
                    "size": maximum,
                }
                self.assertEqual(
                    _validate_file_binding(
                        binding,
                        label=label,
                        maximum=maximum,
                    ),
                    binding,
                )
            with self.subTest(label=label, boundary="maximum-plus-one"):
                with self.assertRaisesRegex(
                    ReleaseAppleToolchainError,
                    "outside its fixed limit",
                ):
                    _validate_file_binding(
                        {
                            "path": "Toolchains/tool",
                            "sha256": "a" * 64,
                            "size": maximum + 1,
                        },
                        label=label,
                        maximum=maximum,
                    )
            for invalid_size in (True, float(maximum)):
                with self.subTest(label=label, invalid_size=invalid_size):
                    with self.assertRaisesRegex(
                        ReleaseAppleToolchainError,
                        "outside its fixed limit",
                    ):
                        _validate_file_binding(
                            {
                                "path": "Toolchains/tool",
                                "sha256": "a" * 64,
                                "size": invalid_size,
                            },
                            label=label,
                            maximum=maximum,
                        )

        self.assertGreater(MAX_CLANG_TOOL_BYTES, MAX_LINKER_TOOL_BYTES)
        representative_universal_clang_size = 300 * 1024 * 1024
        universal_clang_binding = {
            "path": "Toolchains/clang",
            "sha256": "a" * 64,
            "size": representative_universal_clang_size,
        }
        self.assertEqual(
            _validate_file_binding(
                universal_clang_binding,
                label="recorded clang",
                maximum=MAX_CLANG_TOOL_BYTES,
            ),
            universal_clang_binding,
        )
        with self.assertRaisesRegex(
            ReleaseAppleToolchainError,
            "outside its fixed limit",
        ):
            _validate_file_binding(
                universal_clang_binding,
                label="recorded linker",
                maximum=MAX_LINKER_TOOL_BYTES,
            )

    def test_capture_routes_each_tool_through_its_own_size_limit(self) -> None:
        with mock.patch(
            "scripts.release_apple_toolchain._file_record",
            wraps=_file_record,
        ) as file_record:
            capture_release_apple_toolchain(REPOSITORY, self.environment)

        limits = {
            call.kwargs["label"]: call.kwargs["maximum"]
            for call in file_record.call_args_list
        }
        self.assertEqual(limits["selected clang"], MAX_CLANG_TOOL_BYTES)
        self.assertEqual(limits["selected linker"], MAX_LINKER_TOOL_BYTES)

        with mock.patch(
            "scripts.release_apple_toolchain._validate_file_binding",
            wraps=_validate_file_binding,
        ) as validate_file_binding:
            _validate_apple_toolchain_binding_shape(self.observed.binding)
        recorded_limits = {
            call.kwargs["label"]: call.kwargs["maximum"]
            for call in validate_file_binding.call_args_list
        }
        self.assertEqual(recorded_limits["recorded clang"], MAX_CLANG_TOOL_BYTES)
        self.assertEqual(
            recorded_limits["recorded linker"], MAX_LINKER_TOOL_BYTES
        )

    def test_selected_tool_trust_errors_remain_fail_closed_and_specific(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            tool = root / "tool"
            tool.write_bytes(b"tool")
            tool.chmod(0o755)
            observed = tool.lstat()

            for name, mode in (
                ("group", observed.st_mode | stat.S_IWGRP),
                ("other", observed.st_mode | stat.S_IWOTH),
            ):
                trusted_metadata = mock.Mock(
                    st_mode=mode,
                    st_nlink=1,
                    st_uid=0,
                    st_size=observed.st_size,
                )
                with self.subTest(name=name), mock.patch.object(
                    Path,
                    "lstat",
                    return_value=trusted_metadata,
                ):
                    with self.assertRaisesRegex(
                        ReleaseAppleToolchainError,
                        "group- or other-writable",
                    ):
                        _file_record(
                            tool,
                            developer_directory=root,
                            label="selected tool",
                            maximum=1024,
                            executable=True,
                        )

            for name, overrides, diagnostic in (
                ("owner", {"st_uid": 501}, "not root-owned"),
                ("empty", {"st_size": 0}, "is empty"),
                (
                    "oversize",
                    {"st_size": 1025},
                    "exceeds the fixed 1024-byte limit",
                ),
                (
                    "not-regular",
                    {"st_mode": stat.S_IFDIR | 0o755},
                    "not a regular file",
                ),
            ):
                metadata = {
                    "st_mode": observed.st_mode,
                    "st_nlink": 1,
                    "st_uid": 0,
                    "st_size": observed.st_size,
                }
                metadata.update(overrides)
                with self.subTest(name=name), mock.patch.object(
                    Path,
                    "lstat",
                    return_value=mock.Mock(**metadata),
                ):
                    with self.assertRaisesRegex(
                        ReleaseAppleToolchainError,
                        diagnostic,
                    ):
                        _file_record(
                            tool,
                            developer_directory=root,
                            label="selected tool",
                            maximum=1024,
                            executable=True,
                        )

            linked = root / "linked"
            os.link(tool, linked)
            with self.assertRaisesRegex(
                ReleaseAppleToolchainError,
                "multiple hard links",
            ):
                _file_record(
                    tool,
                    developer_directory=root,
                    label="selected tool",
                    maximum=1024,
                    executable=True,
                )

            tool.unlink()
            linked.unlink()
            target = root / "target"
            target.write_bytes(b"tool")
            symlink = root / "symlink"
            symlink.symlink_to(target.name)
            with self.assertRaisesRegex(
                ReleaseAppleToolchainError,
                "canonical real file",
            ):
                _file_record(
                    symlink,
                    developer_directory=root,
                    label="selected tool",
                    maximum=1024,
                    executable=True,
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

    def test_cli_rejects_unexpected_arguments(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY / "scripts/release_apple_toolchain.py"),
                "unexpected-argument",
            ],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        self.assertIn(b"unrecognized arguments", completed.stderr)
        self.assertNotIn(b"verified", completed.stderr)


if __name__ == "__main__":
    unittest.main()
