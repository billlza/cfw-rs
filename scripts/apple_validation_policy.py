"""Keep unsigned CI's observed Apple toolchain separate from production pins."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
from typing import Mapping


VERSION_KEY = "CFW_UNSIGNED_VALIDATION_XCODE_VERSION"
BUILD_KEY = "CFW_UNSIGNED_VALIDATION_XCODE_BUILD_VERSION"
VALIDATION_KEYS = frozenset({VERSION_KEY, BUILD_KEY})
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,2}\Z")
BUILD_RE = re.compile(r"[0-9]+[A-Z][0-9]+[a-z]?\Z")


class AppleValidationPolicyError(ValueError):
    """An unsigned validation selection is incomplete or crosses a role boundary."""


def version_tuple(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise AppleValidationPolicyError("Xcode version is not canonical")
    parts = tuple(int(part) for part in value.split("."))
    return (parts + (0, 0))[:3]


def selected_apple_identity(
    pins: Mapping[str, str], environment: Mapping[str, str], *, role: str | None = None
) -> tuple[str, str]:
    """Return production pins or a complete, explicitly unsigned CI selection.

    The CI selector verifies the installed application and records its observed
    identity. Every consumer still compares that identity with the actual tools.
    Production callers reject the selection, even when it equals production.
    """
    version, build = pins["XCODE_VERSION"], pins["XCODE_BUILD_VERSION"]
    version_tuple(version)
    if not BUILD_RE.fullmatch(build):
        raise AppleValidationPolicyError("production Xcode build is not canonical")
    present = VALIDATION_KEYS & environment.keys()
    if not present:
        return version, build
    if role == "production":
        raise AppleValidationPolicyError("production refuses an unsigned-validation Xcode selection")
    if present != VALIDATION_KEYS:
        raise AppleValidationPolicyError("unsigned-validation Xcode selection is incomplete")
    python = environment.get("CFW_UNSIGNED_VALIDATION_PYTHON", "")
    if not python.startswith("/"):
        raise AppleValidationPolicyError("unsigned-validation Xcode requires the explicit validation role")
    selected_version, selected_build = environment[VERSION_KEY], environment[BUILD_KEY]
    # Hosted images may trail the release machine. Source/SDK compatibility is
    # established by the complete compile and test lanes, not version equality.
    version_tuple(selected_version)
    if not BUILD_RE.fullmatch(selected_build):
        raise AppleValidationPolicyError("unsigned-validation Xcode build is not canonical")
    return selected_version, selected_build


def unsigned_runtime_apple_identity(
    pins: Mapping[str, str], runtime: Path
) -> tuple[str, str]:
    """Admit one CI runtime before verifying a tool built by that runtime."""
    if __package__:
        from .release_python_runtime import ReleasePythonRuntimeError, require_closed_release_runtime
    else:
        from release_python_runtime import ReleasePythonRuntimeError, require_closed_release_runtime
    try:
        require_closed_release_runtime(allow_unsigned_validation=True)
        selected = Path(os.environ["CFW_UNSIGNED_VALIDATION_PYTHON"])
        if not selected.is_absolute() or selected.resolve(strict=True) != runtime:
            raise AppleValidationPolicyError("validation tool runtime differs from its admitted Python")
        return selected_apple_identity(pins, os.environ, role="unsigned-validation")
    except (ReleasePythonRuntimeError, KeyError, OSError) as error:
        raise AppleValidationPolicyError("unsigned-validation runtime admission failed") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()
    if __package__:
        from .publication.graph_model import load_pins
    else:
        from publication.graph_model import load_pins
    try:
        identity = selected_apple_identity(
            load_pins(args.repository / "scripts/dependency_pins.env"), os.environ
        )
    except (AppleValidationPolicyError, KeyError) as error:
        raise SystemExit(f"error: Apple validation policy: {error}") from error
    print(*identity)


if __name__ == "__main__":
    main()
