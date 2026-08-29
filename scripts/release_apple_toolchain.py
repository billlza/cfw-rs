#!/usr/bin/env python3
"""Resolve the Apple linker inputs used by release-critical Rust builds.

The release shell selects one pinned Xcode before Python starts.  This module
turns that selection into a path-independent, content-addressed binding and
returns the exact paths that a closed subprocess environment must use.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Mapping

if __package__:
    from .publication.bounded_process import (
        BoundedProcessError,
        run_bounded_process,
    )
    from .publication.common import PublicationError
    from .publication.graph_model import load_pins
else:
    from publication.bounded_process import BoundedProcessError, run_bounded_process
    from publication.common import PublicationError
    from publication.graph_model import load_pins


APPLE_TOOLCHAIN_DOCUMENT = "cfw-release-apple-linker-binding-v1"
APPLE_TOOLCHAIN_SCHEMA_VERSION = 1
APPLE_XCODEBUILD = Path("/usr/bin/xcodebuild")
APPLE_XCRUN = Path("/usr/bin/xcrun")
MAX_IDENTITY_OUTPUT_BYTES = 4096
# Xcode 26.6 on the hosted release runner is the reviewed Universal build.
# Its two-slice clang is materially larger than the arm64-only distribution,
# while ld remains small.  Keep separate hard resource bounds so admitting the
# reviewed compiler does not unnecessarily widen every linker-input read.
MAX_CLANG_TOOL_BYTES = 512 * 1024 * 1024
MAX_LINKER_TOOL_BYTES = 32 * 1024 * 1024
MAX_SDK_SETTINGS_BYTES = 1024 * 1024
PROCESS_TIMEOUT_SECONDS = 120
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
DEVELOPER_DIRECTORY_PLACEHOLDER = "<selected-xcode>/Contents/Developer"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ReleaseAppleToolchainError(RuntimeError):
    """The selected Apple linker or SDK is missing, mutable, or unpinned."""


@dataclass(frozen=True)
class ReleaseAppleToolchain:
    developer_directory: Path
    clang: Path
    linker: Path
    sdk_root: Path
    deployment_target: str
    binding: dict[str, object]


def _identity_environment(developer_directory: Path) -> dict[str, str]:
    return {
        "DEVELOPER_DIR": str(developer_directory),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": SYSTEM_PATH,
    }


def _identity_output(
    command: list[str],
    *,
    repository: Path,
    environment: dict[str, str],
    label: str,
) -> str:
    try:
        completed = run_bounded_process(
            command,
            cwd=repository,
            environment=environment,
            timeout=PROCESS_TIMEOUT_SECONDS,
            output_limit=MAX_IDENTITY_OUTPUT_BYTES,
        )
    except BoundedProcessError as error:
        raise ReleaseAppleToolchainError(
            f"cannot resolve {label}: {error.reason}"
        ) from error
    if completed.returncode != 0 or completed.stderr:
        raise ReleaseAppleToolchainError(
            f"cannot resolve {label} without diagnostics"
        )
    try:
        output = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseAppleToolchainError(f"{label} is not UTF-8") from error
    output = output.strip()
    if (
        not output
        or len(output.encode("utf-8")) > MAX_IDENTITY_OUTPUT_BYTES
        or any(
            ord(character) < 0x20 and character not in "\n\t"
            for character in output
        )
        or "\x7f" in output
    ):
        raise ReleaseAppleToolchainError(f"{label} is not bounded canonical text")
    return output


def _trusted_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ReleaseAppleToolchainError(f"{label} is not absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except (OSError, RuntimeError) as error:
        raise ReleaseAppleToolchainError(f"{label} is unavailable") from error
    if (
        resolved != path.absolute()
        or not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ReleaseAppleToolchainError(f"{label} is not a trusted real directory")
    return resolved


def _trusted_directory_chain(path: Path, root: Path, label: str) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ReleaseAppleToolchainError(
            f"{label} escaped the selected Xcode application"
        ) from error
    current = root
    _trusted_directory(current, f"{label} root")
    for component in relative.parts:
        current /= component
        _trusted_directory(current, label)


def _relative_path(path: Path, developer_directory: Path, label: str) -> str:
    try:
        relative = path.relative_to(developer_directory)
    except ValueError as error:
        raise ReleaseAppleToolchainError(
            f"{label} escaped the selected Xcode Developer directory"
        ) from error
    if not relative.parts or ".." in relative.parts:
        raise ReleaseAppleToolchainError(f"{label} has an unsafe relative path")
    return relative.as_posix()


def _file_record(
    path: Path,
    *,
    developer_directory: Path,
    label: str,
    maximum: int,
    executable: bool,
) -> dict[str, object]:
    if not path.is_absolute():
        raise ReleaseAppleToolchainError(f"{label} is not absolute")
    try:
        resolved = path.resolve(strict=True)
        before = path.lstat()
    except (OSError, RuntimeError) as error:
        raise ReleaseAppleToolchainError(f"{label} is unavailable") from error
    if resolved != path.absolute() or path.is_symlink():
        raise ReleaseAppleToolchainError(f"{label} is not a canonical real file")
    if not stat.S_ISREG(before.st_mode):
        raise ReleaseAppleToolchainError(f"{label} is not a regular file")
    if before.st_nlink != 1:
        raise ReleaseAppleToolchainError(f"{label} has multiple hard links")
    if before.st_uid != 0:
        raise ReleaseAppleToolchainError(f"{label} is not root-owned")
    if stat.S_IMODE(before.st_mode) & 0o022:
        raise ReleaseAppleToolchainError(
            f"{label} is group- or other-writable"
        )
    if before.st_size <= 0:
        raise ReleaseAppleToolchainError(f"{label} is empty")
    if before.st_size > maximum:
        raise ReleaseAppleToolchainError(
            f"{label} size {before.st_size} exceeds the fixed {maximum}-byte limit"
        )
    if executable and not os.access(path, os.X_OK):
        raise ReleaseAppleToolchainError(f"{label} is not executable")
    _trusted_directory_chain(
        resolved.parent,
        developer_directory.parent.parent,
        f"{label} parent",
    )
    digest = hashlib.sha256()
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
            ):
                raise ReleaseAppleToolchainError(f"{label} changed while opening")
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except OSError as error:
        raise ReleaseAppleToolchainError(f"cannot read {label}") from error
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or after.st_ctime_ns != before.st_ctime_ns
    ):
        raise ReleaseAppleToolchainError(f"{label} changed while hashing")
    return {
        "path": _relative_path(resolved, developer_directory, label),
        "sha256": digest.hexdigest(),
        "size": before.st_size,
    }


def _resolved_xcode_file_path(
    output: str,
    *,
    developer_directory: Path,
    label: str,
) -> Path:
    if "\n" in output or "\t" in output:
        raise ReleaseAppleToolchainError(f"{label} path is not one canonical line")
    candidate = Path(output)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ReleaseAppleToolchainError(f"{label} is unavailable") from error
    if resolved != candidate.absolute():
        raise ReleaseAppleToolchainError(f"{label} path is not canonical")
    _relative_path(resolved, developer_directory, label)
    return resolved


def _resolved_sdk_path(
    output: str,
    *,
    developer_directory: Path,
) -> tuple[Path, Path]:
    if "\n" in output or "\t" in output:
        raise ReleaseAppleToolchainError(
            "macOS SDK path is not one canonical line"
        )
    selected = Path(output)
    expected_parent = (
        developer_directory
        / "Platforms/MacOSX.platform/Developer/SDKs"
    )
    if not selected.is_absolute() or selected.parent != expected_parent:
        raise ReleaseAppleToolchainError(
            "selected macOS SDK escaped the fixed Xcode SDK directory"
        )
    try:
        metadata = selected.lstat()
    except OSError as error:
        raise ReleaseAppleToolchainError("selected macOS SDK is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode):
        try:
            target = os.readlink(selected)
        except OSError as error:
            raise ReleaseAppleToolchainError(
                "cannot read the selected macOS SDK alias"
            ) from error
        if (
            not target
            or Path(target).is_absolute()
            or len(Path(target).parts) != 1
            or target in {".", ".."}
        ):
            raise ReleaseAppleToolchainError(
                "selected macOS SDK alias has an unsafe target"
            )
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ReleaseAppleToolchainError(
                "selected macOS SDK alias is not root-owned and immutable"
            )
        resolved_input = expected_parent / target
    elif stat.S_ISDIR(metadata.st_mode):
        resolved_input = selected
    else:
        raise ReleaseAppleToolchainError(
            "selected macOS SDK is not a directory or fixed alias"
        )
    resolved = _trusted_directory(
        resolved_input,
        "resolved macOS SDK root",
    )
    _trusted_directory_chain(
        selected.parent,
        developer_directory.parent.parent,
        "selected macOS SDK parent",
    )
    _trusted_directory_chain(
        resolved,
        developer_directory.parent.parent,
        "resolved macOS SDK",
    )
    _relative_path(selected, developer_directory, "selected macOS SDK")
    _relative_path(resolved, developer_directory, "resolved macOS SDK")
    return selected, resolved


def capture_release_apple_toolchain(
    repository: Path,
    source_environment: Mapping[str, str] | None = None,
) -> ReleaseAppleToolchain:
    """Validate and bind the Xcode tools that rustc will use for linking."""

    environment_source = (
        os.environ if source_environment is None else source_environment
    )
    try:
        developer_value = environment_source["DEVELOPER_DIR"]
        pins = load_pins(repository / "scripts/dependency_pins.env")
        expected_xcode_version = pins["XCODE_VERSION"]
        expected_xcode_build = pins["XCODE_BUILD_VERSION"]
        expected_deployment_target = pins["MACOS_DEPLOYMENT_TARGET"]
    except (KeyError, OSError, PublicationError, UnicodeDecodeError) as error:
        raise ReleaseAppleToolchainError(
            "Apple release toolchain pins or selection are unavailable"
        ) from error
    if (
        not re.fullmatch(r"[0-9]+(?:[.][0-9]+){1,2}", expected_xcode_version)
        or not re.fullmatch(r"[A-Za-z0-9.]+", expected_xcode_build)
        or not re.fullmatch(
            r"(?:0|[1-9][0-9]*)[.][0-9]+", expected_deployment_target
        )
        or environment_source.get(
            "MACOSX_DEPLOYMENT_TARGET", expected_deployment_target
        )
        != expected_deployment_target
    ):
        raise ReleaseAppleToolchainError(
            "Apple release toolchain selection differs from its pins"
        )
    deployment_target = expected_deployment_target
    developer_directory = _trusted_directory(
        Path(developer_value),
        "selected Xcode Developer directory",
    )
    if developer_directory.parts[-2:] != ("Contents", "Developer"):
        raise ReleaseAppleToolchainError(
            "selected Xcode Developer directory has an unexpected layout"
        )
    _trusted_directory_chain(
        developer_directory,
        developer_directory.parent.parent,
        "selected Xcode Developer directory",
    )
    identity_environment = _identity_environment(developer_directory)
    xcode_identity = _identity_output(
        [str(APPLE_XCODEBUILD), "-version"],
        repository=repository,
        environment=identity_environment,
        label="Xcode identity",
    )
    if xcode_identity != (
        f"Xcode {expected_xcode_version}\nBuild version {expected_xcode_build}"
    ):
        raise ReleaseAppleToolchainError("Xcode identity differs from its release pin")

    clang = _resolved_xcode_file_path(
        _identity_output(
            [str(APPLE_XCRUN), "--find", "clang"],
            repository=repository,
            environment=identity_environment,
            label="selected clang",
        ),
        developer_directory=developer_directory,
        label="selected clang",
    )
    linker = _resolved_xcode_file_path(
        _identity_output(
            [str(APPLE_XCRUN), "--find", "ld"],
            repository=repository,
            environment=identity_environment,
            label="selected linker",
        ),
        developer_directory=developer_directory,
        label="selected linker",
    )
    selected_sdk_root, resolved_sdk_root = _resolved_sdk_path(
        _identity_output(
            [str(APPLE_XCRUN), "--sdk", "macosx", "--show-sdk-path"],
            repository=repository,
            environment=identity_environment,
            label="macOS SDK path",
        ),
        developer_directory=developer_directory,
    )
    sdk_version = _identity_output(
        [str(APPLE_XCRUN), "--sdk", "macosx", "--show-sdk-version"],
        repository=repository,
        environment=identity_environment,
        label="macOS SDK version",
    )
    if not re.fullmatch(r"[0-9]+(?:[.][0-9]+){1,2}", sdk_version):
        raise ReleaseAppleToolchainError("macOS SDK version is malformed")
    if selected_sdk_root.name not in {
        "MacOSX.sdk",
        f"MacOSX{sdk_version}.sdk",
    }:
        raise ReleaseAppleToolchainError(
            "selected macOS SDK name differs from its version"
        )

    binding: dict[str, object] = {
        "clang": _file_record(
            clang,
            developer_directory=developer_directory,
            label="selected clang",
            maximum=MAX_CLANG_TOOL_BYTES,
            executable=True,
        ),
        "deployment_target": deployment_target,
        "developer_directory": DEVELOPER_DIRECTORY_PLACEHOLDER,
        "document": APPLE_TOOLCHAIN_DOCUMENT,
        "ld": _file_record(
            linker,
            developer_directory=developer_directory,
            label="selected linker",
            maximum=MAX_LINKER_TOOL_BYTES,
            executable=True,
        ),
        "schema_version": APPLE_TOOLCHAIN_SCHEMA_VERSION,
        "sdk": {
            "resolved_path": _relative_path(
                resolved_sdk_root,
                developer_directory,
                "resolved macOS SDK root",
            ),
            "selected_path": _relative_path(
                selected_sdk_root,
                developer_directory,
                "selected macOS SDK root",
            ),
            "settings": _file_record(
                resolved_sdk_root / "SDKSettings.json",
                developer_directory=developer_directory,
                label="macOS SDK settings",
                maximum=MAX_SDK_SETTINGS_BYTES,
                executable=False,
            ),
            "version": sdk_version,
        },
        "xcode_build_version": expected_xcode_build,
        "xcode_version": expected_xcode_version,
    }
    return ReleaseAppleToolchain(
        developer_directory=developer_directory,
        clang=clang,
        linker=linker,
        sdk_root=selected_sdk_root,
        deployment_target=deployment_target,
        binding=binding,
    )


def _require_exact_mapping(
    value: object,
    fields: set[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseAppleToolchainError(f"{label} has an unexpected field set")
    return value


def _require_bounded_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value.encode("utf-8")) > MAX_IDENTITY_OUTPUT_BYTES
        or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in value
        )
    ):
        raise ReleaseAppleToolchainError(f"{label} is not bounded canonical text")
    return value


def _validate_file_binding(
    value: object,
    *,
    label: str,
    maximum: int,
) -> dict[str, object]:
    value = _require_exact_mapping(value, {"path", "sha256", "size"}, label)
    path = _require_bounded_text(value["path"], f"{label} path")
    if Path(path).is_absolute() or ".." in Path(path).parts:
        raise ReleaseAppleToolchainError(f"{label} path is not safe and relative")
    digest = value["sha256"]
    size = value["size"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ReleaseAppleToolchainError(f"{label} digest is not canonical")
    if type(size) is not int or size <= 0 or size > maximum:
        raise ReleaseAppleToolchainError(f"{label} size is outside its fixed limit")
    return value


def _validate_apple_toolchain_binding_shape(
    value: object,
) -> dict[str, object]:
    value = _require_exact_mapping(
        value,
        {
            "clang",
            "deployment_target",
            "developer_directory",
            "document",
            "ld",
            "schema_version",
            "sdk",
            "xcode_build_version",
            "xcode_version",
        },
        "Apple linker binding",
    )
    if (
        value["document"] != APPLE_TOOLCHAIN_DOCUMENT
        or type(value["schema_version"]) is not int
        or value["schema_version"] != APPLE_TOOLCHAIN_SCHEMA_VERSION
        or value["developer_directory"] != DEVELOPER_DIRECTORY_PLACEHOLDER
    ):
        raise ReleaseAppleToolchainError("Apple linker binding policy is inconsistent")
    deployment_target = _require_bounded_text(
        value["deployment_target"], "Apple deployment target"
    )
    xcode_version = _require_bounded_text(
        value["xcode_version"], "Xcode version"
    )
    xcode_build_version = _require_bounded_text(
        value["xcode_build_version"], "Xcode build version"
    )
    if (
        not re.fullmatch(r"(?:0|[1-9][0-9]*)[.][0-9]+", deployment_target)
        or not re.fullmatch(r"[0-9]+(?:[.][0-9]+){1,2}", xcode_version)
        or not re.fullmatch(r"[A-Za-z0-9.]+", xcode_build_version)
    ):
        raise ReleaseAppleToolchainError("Apple linker binding versions are malformed")
    _validate_file_binding(
        value["clang"],
        label="recorded clang",
        maximum=MAX_CLANG_TOOL_BYTES,
    )
    _validate_file_binding(
        value["ld"],
        label="recorded linker",
        maximum=MAX_LINKER_TOOL_BYTES,
    )
    sdk = _require_exact_mapping(
        value["sdk"],
        {"resolved_path", "selected_path", "settings", "version"},
        "recorded macOS SDK",
    )
    for field in ("resolved_path", "selected_path"):
        sdk_path = _require_bounded_text(
            sdk[field], f"recorded macOS SDK {field}"
        )
        if Path(sdk_path).is_absolute() or ".." in Path(sdk_path).parts:
            raise ReleaseAppleToolchainError(
                f"recorded macOS SDK {field} is not safe and relative"
            )
    sdk_version = _require_bounded_text(
        sdk["version"], "recorded macOS SDK version"
    )
    if not re.fullmatch(r"[0-9]+(?:[.][0-9]+){1,2}", sdk_version):
        raise ReleaseAppleToolchainError(
            "recorded macOS SDK version is malformed"
        )
    _validate_file_binding(
        sdk["settings"],
        label="recorded macOS SDK settings",
        maximum=MAX_SDK_SETTINGS_BYTES,
    )
    return value


def validate_recorded_release_apple_toolchain(
    value: object,
    repository: Path,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    value = _validate_apple_toolchain_binding_shape(value)
    observed = capture_release_apple_toolchain(repository, source_environment)
    if value != observed.binding:
        raise ReleaseAppleToolchainError(
            "recorded Apple linker inputs differ from the selected toolchain"
        )
    return value


def main() -> None:
    """Fail fast on the exact production Apple linker-input contract."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        observed = capture_release_apple_toolchain(repository)
    except (OSError, ReleaseAppleToolchainError) as error:
        raise SystemExit(f"error: Apple release toolchain: {error}") from error
    binding = observed.binding
    print(
        "Apple release toolchain verified: "
        f"Xcode {binding['xcode_version']} ({binding['xcode_build_version']}), "
        f"clang={binding['clang']['size']} bytes, "
        f"ld={binding['ld']['size']} bytes, "
        f"macOS SDK {binding['sdk']['version']}"
    )


__all__ = [
    "APPLE_TOOLCHAIN_DOCUMENT",
    "APPLE_TOOLCHAIN_SCHEMA_VERSION",
    "DEVELOPER_DIRECTORY_PLACEHOLDER",
    "ReleaseAppleToolchain",
    "ReleaseAppleToolchainError",
    "capture_release_apple_toolchain",
    "validate_recorded_release_apple_toolchain",
]


if __name__ == "__main__":
    main()
