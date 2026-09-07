#!/usr/bin/env python3
"""Observe and bind the private physical environment used for GA acceptance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Final, Sequence

if __package__:
    from .harness.physical_machine_identity import (
        PhysicalMachineIdentityError,
        collect_boot_environment_sha256,
        collect_machine_identity,
        validate_physical_hardware_model,
    )
    from .publication.bounded_process import BoundedProcessError, run_bounded_process
else:
    from harness.physical_machine_identity import (
        PhysicalMachineIdentityError,
        collect_boot_environment_sha256,
        collect_machine_identity,
        validate_physical_hardware_model,
    )
    from publication.bounded_process import (
        BoundedProcessError,
        run_bounded_process,
    )


DOCUMENT: Final = "cfm-ga-environment-identity-v1"
SCHEMA_VERSION: Final = 1
DOMAIN: Final = DOCUMENT.encode("ascii") + b"\0"
MAX_COMMAND_OUTPUT_BYTES: Final = 4096
COMMAND_TIMEOUT_SECONDS: Final = 10
SYSTEM_ENVIRONMENT: Final = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
}
SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
MACOS_VERSION_PATTERN: Final = re.compile(
    r"^[1-9][0-9]{0,2}\.[0-9]{1,3}(?:\.[0-9]{1,3})?$"
)
MACOS_BUILD_PATTERN: Final = re.compile(r"^[0-9]{2}[A-Z][0-9]{1,6}[a-z]?$")
ENVIRONMENT_FIELDS: Final = frozenset(
    {
        "architecture",
        "boot_environment_sha256",
        "document",
        "hardware_model",
        "machine_sha256",
        "macos_build_version",
        "macos_product_version",
        "physical_nonvirtualized",
        "schema_version",
    }
)


class GAAcceptanceEnvironmentError(ValueError):
    """The GA environment observation or binding is invalid."""


Runner = Callable[..., subprocess.CompletedProcess[bytes]]
EnvironmentObserver = Callable[[], dict[str, Any]]


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _command_text(
    command: Sequence[str], *, runner: Runner | None = None
) -> str:
    try:
        result = (
            run_bounded_process(
                command,
                cwd=Path("/"),
                environment=SYSTEM_ENVIRONMENT,
                timeout=COMMAND_TIMEOUT_SECONDS,
                output_limit=MAX_COMMAND_OUTPUT_BYTES,
            )
            if runner is None
            else runner(
                list(command),
                input=b"",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=SYSTEM_ENVIRONMENT,
                timeout=COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
        )
    except (OSError, subprocess.TimeoutExpired, BoundedProcessError) as error:
        raise GAAcceptanceEnvironmentError(
            f"GA environment command failed closed: {command[0]}"
        ) from error
    if (
        result.returncode != 0
        or result.stderr
        or not result.stdout
        or len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES
    ):
        raise GAAcceptanceEnvironmentError(
            f"GA environment command output is invalid: {command[0]}"
        )
    try:
        value = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise GAAcceptanceEnvironmentError(
            f"GA environment command output is not UTF-8: {command[0]}"
        ) from error
    if (
        not value
        or len(value.encode("utf-8")) > 128
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise GAAcceptanceEnvironmentError(
            f"GA environment command output is not bounded text: {command[0]}"
        )
    return value


def validate_environment(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ENVIRONMENT_FIELDS:
        raise GAAcceptanceEnvironmentError("GA environment document shape is invalid")
    if (
        value["document"] != DOCUMENT
        or type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
    ):
        raise GAAcceptanceEnvironmentError("GA environment schema is unsupported")
    if value["architecture"] != "arm64" or value["physical_nonvirtualized"] is not True:
        raise GAAcceptanceEnvironmentError(
            "GA acceptance requires a physical Apple Silicon environment"
        )
    try:
        validate_physical_hardware_model(value["hardware_model"])
    except (PhysicalMachineIdentityError, TypeError) as error:
        raise GAAcceptanceEnvironmentError("GA hardware model is invalid") from error
    for field in ("machine_sha256", "boot_environment_sha256"):
        if not isinstance(value[field], str) or SHA256_PATTERN.fullmatch(value[field]) is None:
            raise GAAcceptanceEnvironmentError(f"GA environment {field} is invalid")
    if (
        not isinstance(value["macos_product_version"], str)
        or MACOS_VERSION_PATTERN.fullmatch(value["macos_product_version"]) is None
    ):
        raise GAAcceptanceEnvironmentError("GA macOS product version is invalid")
    if (
        not isinstance(value["macos_build_version"], str)
        or MACOS_BUILD_PATTERN.fullmatch(value["macos_build_version"]) is None
    ):
        raise GAAcceptanceEnvironmentError("GA macOS build version is invalid")
    return dict(value)


def environment_sha256(value: object) -> str:
    # Level 1 release-integrity identity: this detects stale or mixed private
    # evidence.  It is not authentication and does not claim to resist the
    # repository owner.
    normalized = validate_environment(value)
    return hashlib.sha256(DOMAIN + canonical_json(normalized)).hexdigest()


def observe_environment(*, runner: Runner | None = None) -> dict[str, Any]:
    try:
        machine = collect_machine_identity(runner=runner)
        boot_environment_sha256 = collect_boot_environment_sha256(runner=runner)
    except (
        OSError,
        subprocess.TimeoutExpired,
        BoundedProcessError,
        PhysicalMachineIdentityError,
    ) as error:
        raise GAAcceptanceEnvironmentError(
            "GA physical environment identity could not be observed"
        ) from error
    return validate_environment(
        {
            "architecture": machine.architecture,
            "boot_environment_sha256": boot_environment_sha256,
            "document": DOCUMENT,
            "hardware_model": machine.hardware_model,
            "machine_sha256": machine.machine_sha256,
            "macos_build_version": _command_text(
                ("/usr/bin/sw_vers", "-buildVersion"), runner=runner
            ),
            "macos_product_version": _command_text(
                ("/usr/bin/sw_vers", "-productVersion"), runner=runner
            ),
            "physical_nonvirtualized": True,
            "schema_version": SCHEMA_VERSION,
        }
    )


def require_same_environment(
    expected: object,
    observed: object,
    *,
    label: str = "GA environment",
) -> dict[str, Any]:
    normalized_expected = validate_environment(expected)
    normalized_observed = validate_environment(observed)
    if normalized_observed != normalized_expected:
        raise GAAcceptanceEnvironmentError(f"{label} changed")
    return normalized_observed


def self_check() -> None:
    example = {
        "architecture": "arm64",
        "boot_environment_sha256": "b" * 64,
        "document": DOCUMENT,
        "hardware_model": "Mac16,1",
        "machine_sha256": "a" * 64,
        "macos_build_version": "26A5388g",
        "macos_product_version": "27.0",
        "physical_nonvirtualized": True,
        "schema_version": SCHEMA_VERSION,
    }
    expected = "e29e75d546de2ee3bce00fdbf4c136e7cd6dfe289fee8082ee9fcabecc78d412"
    if environment_sha256(example) != expected:
        raise GAAcceptanceEnvironmentError("GA environment self-check drifted")


if __name__ == "__main__":
    self_check()
