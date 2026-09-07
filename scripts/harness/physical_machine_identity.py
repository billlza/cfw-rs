#!/usr/bin/env python3
"""Derive the private physical-evidence machine digest from fixed macOS facts."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
from typing import Any, Callable, Sequence

if __package__:
    from .raw_artifacts import EVIDENCE_PROFILE, canonical_json
else:  # pragma: no cover - direct script entrypoint
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from raw_artifacts import EVIDENCE_PROFILE, canonical_json  # type: ignore


DOCUMENT = EVIDENCE_PROFILE["machine_identity_scheme"]
SCHEMA_VERSION = 1
DOMAIN = DOCUMENT.encode("ascii") + b"\0"
BOOT_DOCUMENT = EVIDENCE_PROFILE["boot_environment_scheme"]
BOOT_DOMAIN = BOOT_DOCUMENT.encode("ascii") + b"\0"
MAX_COMMAND_OUTPUT = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 10
SYSTEM_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
}
UUID_PATTERN = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
PHYSICAL_MODEL_PATTERN = re.compile(
    r"^(?:Mac(?:BookAir|BookPro|mini|Pro|Studio)?|iMac(?:Pro)?)"
    r"[1-9][0-9]{0,2},[1-9][0-9]{0,2}$"
)
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


class PhysicalMachineIdentityError(ValueError):
    """The local hardware identity could not be derived without ambiguity."""


Runner = Callable[..., subprocess.CompletedProcess[bytes]]


@dataclass(frozen=True)
class PhysicalMachineIdentity:
    machine_sha256: str
    hardware_model: str
    architecture: str


def _validate_result(
    command: Sequence[str], result: subprocess.CompletedProcess[bytes]
) -> bytes:
    if result.returncode != 0 or result.stderr:
        raise PhysicalMachineIdentityError(
            f"machine identity command failed closed: {command[0]}"
        )
    if not result.stdout or len(result.stdout) > MAX_COMMAND_OUTPUT:
        raise PhysicalMachineIdentityError(
            f"machine identity command output is outside bounds: {command[0]}"
        )
    return result.stdout


def _run_bounded(command: Sequence[str]) -> bytes:
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            env=SYSTEM_ENVIRONMENT,
        )
        try:
            returncode = process.wait(timeout=COMMAND_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            raise PhysicalMachineIdentityError(
                f"machine identity command timed out: {command[0]}"
            ) from error
        stdout_size = os.fstat(stdout_file.fileno()).st_size
        stderr_size = os.fstat(stderr_file.fileno()).st_size
        if stdout_size > MAX_COMMAND_OUTPUT or stderr_size > MAX_COMMAND_OUTPUT:
            raise PhysicalMachineIdentityError(
                f"machine identity command output is outside bounds: {command[0]}"
            )
        stdout_file.seek(0)
        stderr_file.seek(0)
        return _validate_result(
            command,
            subprocess.CompletedProcess(
                list(command), returncode, stdout_file.read(), stderr_file.read()
            ),
        )


def _run(command: Sequence[str], *, runner: Runner | None = None) -> bytes:
    if runner is None:
        return _run_bounded(command)
    try:
        result = runner(
            list(command),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SYSTEM_ENVIRONMENT,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise PhysicalMachineIdentityError(
            f"machine identity command timed out: {command[0]}"
        ) from error
    return _validate_result(command, result)


def _text(data: bytes, label: str) -> str:
    try:
        value = data.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise PhysicalMachineIdentityError(f"{label} is not UTF-8") from error
    if (
        not value
        or len(value.encode("utf-8")) > 128
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PhysicalMachineIdentityError(f"{label} is not bounded printable text")
    return value


def _platform_uuid(data: bytes) -> str:
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise PhysicalMachineIdentityError("ioreg output is not a plist") from error
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise PhysicalMachineIdentityError("ioreg output has an unexpected root")
    platform_uuid = value[0].get("IOPlatformUUID")
    if (
        not isinstance(platform_uuid, str)
        or not UUID_PATTERN.fullmatch(platform_uuid)
        or platform_uuid.lower() == ZERO_UUID
    ):
        raise PhysicalMachineIdentityError("IOPlatformUUID is missing or malformed")
    return platform_uuid.lower()


def derive_boot_environment_sha256(
    *, volume_uuid: str, volume_group_uuid: str
) -> str:
    for value, label in (
        (volume_uuid, "volume UUID"),
        (volume_group_uuid, "volume-group UUID"),
    ):
        if not UUID_PATTERN.fullmatch(value) or value.lower() == ZERO_UUID:
            raise PhysicalMachineIdentityError(f"{label} is malformed")
    payload = {
        "document": BOOT_DOCUMENT,
        "schema_version": 1,
        "volume_group_uuid": volume_group_uuid.lower(),
        "volume_uuid": volume_uuid.lower(),
    }
    return hashlib.sha256(BOOT_DOMAIN + canonical_json(payload)).hexdigest()


def _boot_environment(data: bytes) -> str:
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise PhysicalMachineIdentityError("diskutil output is not a plist") from error
    if not isinstance(value, dict):
        raise PhysicalMachineIdentityError("diskutil output has an unexpected root")
    expected = {
        "MountPoint": "/",
        "Bootable": True,
        "FilesystemType": "apfs",
        "SystemImage": False,
        "Sealed": "Yes",
    }
    for field, wanted in expected.items():
        if value.get(field) != wanted:
            raise PhysicalMachineIdentityError(
                f"boot environment {field} is unsupported"
            )
    volume_uuid = value.get("VolumeUUID")
    volume_group_uuid = value.get("APFSVolumeGroupID")
    if not isinstance(volume_uuid, str) or not isinstance(volume_group_uuid, str):
        raise PhysicalMachineIdentityError(
            "boot environment UUIDs are missing"
        )
    return derive_boot_environment_sha256(
        volume_uuid=volume_uuid,
        volume_group_uuid=volume_group_uuid,
    )


def validate_physical_hardware_model(value: str) -> str:
    if not isinstance(value, str) or not PHYSICAL_MODEL_PATTERN.fullmatch(value):
        raise PhysicalMachineIdentityError(
            "hardware model is not a physical Apple Mac identifier"
        )
    return value


def derive_machine_sha256(
    *,
    platform_uuid: str,
    hardware_model: str,
    architecture: str,
    virtualization_present: bool,
) -> str:
    if (
        not UUID_PATTERN.fullmatch(platform_uuid)
        or platform_uuid.lower() == ZERO_UUID
    ):
        raise PhysicalMachineIdentityError("IOPlatformUUID is malformed")
    validate_physical_hardware_model(hardware_model)
    if architecture != "arm64":
        raise PhysicalMachineIdentityError("physical evidence requires arm64")
    if virtualization_present is not False:
        raise PhysicalMachineIdentityError(
            "physical evidence rejects virtualized execution"
        )
    payload: dict[str, Any] = {
        "architecture": architecture,
        "document": DOCUMENT,
        "hardware_model": hardware_model,
        "io_platform_uuid": platform_uuid.lower(),
        "schema_version": SCHEMA_VERSION,
        "virtualization_present": False,
    }
    return hashlib.sha256(DOMAIN + canonical_json(payload)).hexdigest()


def collect_machine_identity(*, runner: Runner | None = None) -> PhysicalMachineIdentity:
    operating_system = _text(_run(("/usr/bin/uname", "-s"), runner=runner), "OS")
    if operating_system != "Darwin":
        raise PhysicalMachineIdentityError("physical evidence requires Darwin")
    architecture = _text(
        _run(("/usr/bin/uname", "-m"), runner=runner), "architecture"
    )
    hardware_model = _text(
        _run(("/usr/sbin/sysctl", "-n", "hw.model"), runner=runner),
        "hardware model",
    )
    validate_physical_hardware_model(hardware_model)
    virtualization = _text(
        _run(("/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"), runner=runner),
        "virtualization indicator",
    )
    if virtualization not in {"0", "1"}:
        raise PhysicalMachineIdentityError(
            "virtualization indicator is not canonical"
        )
    platform_uuid = _platform_uuid(
        _run(
            (
                "/usr/sbin/ioreg",
                "-a",
                "-r",
                "-l",
                "-d",
                "1",
                "-c",
                "IOPlatformExpertDevice",
            ),
            runner=runner,
        )
    )
    digest = derive_machine_sha256(
        platform_uuid=platform_uuid,
        hardware_model=hardware_model,
        architecture=architecture,
        virtualization_present=virtualization == "1",
    )
    return PhysicalMachineIdentity(
        machine_sha256=digest,
        hardware_model=hardware_model,
        architecture=architecture,
    )


def collect_machine_sha256(*, runner: Runner | None = None) -> str:
    return collect_machine_identity(runner=runner).machine_sha256


def collect_boot_environment_sha256(*, runner: Runner | None = None) -> str:
    return _boot_environment(
        _run(("/usr/sbin/diskutil", "info", "-plist", "/"), runner=runner)
    )


def self_check() -> None:
    expected = "e16dea85471fe6c16032fa874c25e3803d6142acedc805fb4ef04b2b190bb902"
    actual = derive_machine_sha256(
        platform_uuid="01234567-89ab-cdef-0123-456789abcdef",
        hardware_model="Mac16,1",
        architecture="arm64",
        virtualization_present=False,
    )
    if actual != expected:
        raise PhysicalMachineIdentityError("machine identity self-check drifted")
    boot_expected = "d474c92f7822316f5ebcf273cae689fdfa2c5348f9c2d73ff6dd8b24bb42cb63"
    boot_actual = derive_boot_environment_sha256(
        volume_uuid="11111111-2222-3333-4444-555555555555",
        volume_group_uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    if boot_actual != boot_expected:
        raise PhysicalMachineIdentityError("boot environment self-check drifted")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--self-check", action="store_true")
    actions.add_argument("--boot-environment", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.self_check:
            self_check()
            print("physical machine identity self-check ok")
        elif arguments.boot_environment:
            print(collect_boot_environment_sha256())
        else:
            print(collect_machine_sha256())
    except (OSError, PhysicalMachineIdentityError, subprocess.SubprocessError) as error:
        raise SystemExit(f"error: physical machine identity failed closed: {error}") from error


if __name__ == "__main__":
    main()
