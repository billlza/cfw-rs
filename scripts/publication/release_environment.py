"""Shared fail-closed Python adapter for the release tool environment."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import re

from .bounded_process import BoundedProcessError, run_bounded_process
from .common import PublicationError
from .graph_model import load_pins

if __package__ and __package__.startswith("scripts."):
    from scripts.release_cargo_inputs import (
        ReleaseCargoInputsError,
        verify_workspace_cargo_inputs,
        workspace_input_root,
    )
else:
    from release_cargo_inputs import (
        ReleaseCargoInputsError,
        verify_workspace_cargo_inputs,
        workspace_input_root,
    )


IDENTITY_TIMEOUT_SECONDS = 120
APPLE_XCODEBUILD = "/usr/bin/xcodebuild"
APPLE_XCRUN = "/usr/bin/xcrun"
APPLE_SWIFT = "/usr/bin/swift"
SYSTEM_PATH = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
RELEASE_ENVIRONMENT_SCRIPT = "scripts/release_tool_environment.sh"
MAX_RELEASE_ENVIRONMENT_BYTES = 1024 * 1024
MAX_RELEASE_ENVIRONMENT_DIAGNOSTIC_BYTES = 64 * 1024
MAX_RELEASE_ENVIRONMENT_PROCESS_BYTES = (
    MAX_RELEASE_ENVIRONMENT_BYTES + MAX_RELEASE_ENVIRONMENT_DIAGNOSTIC_BYTES
)
RELEASE_ENVIRONMENT_COMMAND = r'''
set -euo pipefail
repository="$1"
release_role="$2"
source "$repository/scripts/dependency_pins.env"
source "$repository/scripts/release_tool_environment.sh"
cfw_seal_release_tool_environment "$release_role"
cfw_select_release_apple_toolchain
/usr/bin/env -0
'''

_REQUIRED_ENVIRONMENT = {
    "DEVELOPER_DIR",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
}
_OPERATIONAL_ENVIRONMENT = {
    "CFW_BUILD_NUMBER",
    "CFW_GO_MODULE_CACHE_TREE_SHA256",
    "CFW_GO_TOOLCHAIN_TREE_SHA256",
    "CFW_GO_TOOLS_TREE_SHA256",
    "CFW_NATIVE_DERIVED_DATA",
    "CFW_NATIVE_PRODUCTS_OUTPUT",
    "CFW_RELEASE_SOURCE_SHA256",
    "CFW_REPOSITORY_COMMIT",
    "CFW_TOOLCHAIN_ROOT",
    "CFW_UNSIGNED_VALIDATION_PYTHON",
    "HOST_PROVISIONING_PROFILE_PATH",
    "MACOS_SIGN_IDENTITY",
    "NOTARY_PROFILE",
    "PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER",
    "PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER",
}
_BOOTSTRAP_ENVIRONMENT = _OPERATIONAL_ENVIRONMENT | {"DEVELOPER_DIR"}
_BOOTSTRAP_FIXED_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": ":".join(SYSTEM_PATH),
}


def _release_environment_bootstrap(
    source_environment: dict[str, str],
) -> dict[str, str]:
    """Close the environment before starting the shell that seals it."""
    if any(name.startswith("BASH_FUNC_") for name in source_environment):
        raise PublicationError(
            "exported shell functions are forbidden in the release environment"
        )
    if source_environment.get("POSIXLY_CORRECT") or source_environment.get(
        "BASH_COMPAT"
    ):
        raise PublicationError(
            "alternate Bash compatibility modes are forbidden for release tooling"
        )
    bootstrap = dict(_BOOTSTRAP_FIXED_ENVIRONMENT)
    bootstrap.update(
        (name, source_environment[name])
        for name in _BOOTSTRAP_ENVIRONMENT
        if name in source_environment
    )
    return bootstrap


def identity_output(
    argv: list[str],
    repository: Path,
    label: str,
    environment: dict[str, str],
    maximum: int = 512,
) -> str:
    try:
        completed = run_bounded_process(
            argv,
            cwd=repository,
            environment=environment,
            timeout=IDENTITY_TIMEOUT_SECONDS,
            output_limit=maximum,
        )
    except BoundedProcessError as error:
        if error.reason == "output-limit":
            reason = "output exceeded its fixed bound"
        elif error.reason == "timeout":
            reason = "command timed out"
        else:
            reason = f"process boundary failed: {error}"
        raise PublicationError(
            f"cannot resolve the {label} toolchain identity: {reason}"
        ) from error
    if completed.returncode != 0:
        raise PublicationError(
            f"cannot resolve the {label} toolchain identity: exit {completed.returncode}"
        )
    if completed.stderr:
        raise PublicationError(f"the {label} toolchain identity emitted diagnostics")
    try:
        text = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PublicationError(f"the {label} toolchain identity is not UTF-8") from error
    identity = "; ".join(line.strip() for line in text.splitlines() if line.strip())
    if not identity or len(identity) > maximum:
        raise PublicationError(f"the {label} toolchain identity is empty or unbounded")
    return identity


def _is_real_executable(path: Path) -> bool:
    try:
        return (
            path.is_file()
            and not path.is_symlink()
            and os.access(path, os.X_OK)
            and path.stat().st_nlink == 1
        )
    except OSError:
        return False


def _is_real_directory(path: Path) -> bool:
    try:
        return path.is_dir() and not path.is_symlink()
    except OSError:
        return False


def release_tool_environment(
    repository: Path,
    pins: dict[str, str],
    source_environment: dict[str, str] | None = None,
    *,
    role: str = "production",
) -> dict[str, str]:
    """Return the one closed environment shared by release identity and execution."""
    if pins != load_pins(repository / "scripts/dependency_pins.env"):
        raise PublicationError("release environment pins differ from the repository pins")
    if role not in {"production", "unsigned-validation", "tool-bootstrap"}:
        raise PublicationError("release environment role is invalid")
    environment_contract = repository / RELEASE_ENVIRONMENT_SCRIPT
    if not environment_contract.is_file() or environment_contract.is_symlink():
        raise PublicationError("release tool environment contract is missing or a symlink")
    source = dict(os.environ if source_environment is None else source_environment)
    bootstrap_environment = _release_environment_bootstrap(source)
    try:
        completed = run_bounded_process(
            [
                "/bin/bash",
                "-p",
                "-c",
                RELEASE_ENVIRONMENT_COMMAND,
                "release-tool-environment",
                str(repository),
                role,
            ],
            cwd=repository,
            environment=bootstrap_environment,
            timeout=IDENTITY_TIMEOUT_SECONDS,
            output_limit=MAX_RELEASE_ENVIRONMENT_PROCESS_BYTES,
        )
    except BoundedProcessError as error:
        raise PublicationError(
            f"cannot construct the release tool environment: {error}"
        ) from error
    if (
        completed.returncode != 0
        or len(completed.stdout) > MAX_RELEASE_ENVIRONMENT_BYTES
        or len(completed.stderr) > MAX_RELEASE_ENVIRONMENT_DIAGNOSTIC_BYTES
    ):
        diagnostics = completed.stderr.decode("utf-8", "replace").strip()
        raise PublicationError(
            "cannot construct the release tool environment"
            + (f": {diagnostics}" if diagnostics else "")
        )
    if completed.stderr or not completed.stdout.endswith(b"\0"):
        raise PublicationError("release tool environment emitted diagnostics or malformed output")

    environment: dict[str, str] = {}
    try:
        for record in completed.stdout[:-1].split(b"\0"):
            name_bytes, separator, value_bytes = record.partition(b"=")
            if not separator:
                raise ValueError("missing separator")
            name = name_bytes.decode("utf-8")
            value = value_bytes.decode("utf-8")
            if not name or name in environment:
                raise ValueError("empty or duplicate name")
            environment[name] = value
    except (UnicodeDecodeError, ValueError) as error:
        raise PublicationError("release tool environment output is malformed") from error

    home_value = environment.get("HOME")
    if not home_value or not Path(home_value).is_absolute():
        raise PublicationError("release tool environment has no absolute HOME")
    python_version = pins.get("PYTHON_VERSION")
    if not isinstance(python_version, str) or not re.fullmatch(
        r"3[.][0-9]+[.][0-9]+", python_version
    ):
        raise PublicationError("release Python version pin is invalid")
    try:
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve(strict=True)
        release_home = Path(home_value).resolve(strict=True)
        rust_root = (
            release_home
            / ".rustup"
            / "toolchains"
            / f"{pins['RUST_VERSION']}-aarch64-apple-darwin"
        )
        rust_bin = rust_root / "bin"
        policy_tool_root = (
            release_home
            / ".cfm-release-tooling"
            / f"policy-{pins['CARGO_AUDIT_VERSION']}-{pins['CARGO_DENY_VERSION']}"
        )
        cargo_aux_bin = policy_tool_root / "bin"
        python_series = python_version.rsplit(".", 1)[0]
        production_python_root = (
            Path("/opt/homebrew/Cellar")
            / f"python@{python_series}"
            / python_version
            / "Frameworks/Python.framework/Versions"
            / python_series
        )
        python_executable = Path(
            environment["CFW_RELEASE_PYTHON_EXECUTABLE"]
        ).resolve(strict=True)
        python_runtime = Path(environment["CFW_RELEASE_PYTHON_RUNTIME"]).resolve(
            strict=True
        )
        python_stdlib = Path(environment["CFW_RELEASE_PYTHON_STDLIB"]).resolve(
            strict=True
        )
        path_entries = environment["PATH"].split(":")
        if len(path_entries) != 6:
            raise PublicationError("release PATH does not contain the exact closed layout")
        validation_python = environment.get("CFW_UNSIGNED_VALIDATION_PYTHON")
        validation_python_resolved = (
            Path(validation_python).resolve(strict=True) if validation_python else None
        )
        python_bin_dir = (
            Path(validation_python).parent
            if validation_python is not None
            else production_python_root / "bin"
        )
        python_bin = python_bin_dir / "python3"
        python_bin_resolved = python_bin.resolve(strict=True)
        developer_dir = Path(environment["DEVELOPER_DIR"]).resolve(strict=True)
    except (KeyError, OSError) as error:
        raise PublicationError("release tool environment paths are invalid") from error
    expected_path = ":".join((*SYSTEM_PATH, str(rust_bin), str(cargo_aux_bin)))
    required_environment = _REQUIRED_ENVIRONMENT | {
        "CFW_RELEASE_CARGO_EXECUTABLE",
        "CFW_RELEASE_POLICY_TOOL_ROOT",
        "CFW_RELEASE_PYTHON_EXECUTABLE",
        "CFW_RELEASE_PYTHON_RUNTIME",
        "CFW_RELEASE_PYTHON_STDLIB",
        "CFW_RELEASE_RUSTC_EXECUTABLE",
    }
    if role != "tool-bootstrap":
        required_environment |= {
            "CFW_RELEASE_CARGO_AUDIT_EXECUTABLE",
            "CFW_RELEASE_CARGO_DENY_EXECUTABLE",
            "CFW_RELEASE_CARGO_INPUT_ROOT",
            "CFW_RELEASE_CARGO_LOCK_SHA256",
            "CFW_RELEASE_CARGO_VENDOR_ROOT",
            "CFW_RELEASE_CARGO_VENDOR_SHA256",
        }
    allowed_environment = required_environment | _OPERATIONAL_ENVIRONMENT | {"_"}
    trusted_executables = [
        rust_bin / "rustc",
        rust_bin / "cargo",
        python_executable,
        python_runtime,
    ]
    if role != "tool-bootstrap":
        trusted_executables.extend(
            (cargo_aux_bin / "cargo-audit", cargo_aux_bin / "cargo-deny")
        )
    if (
        release_home != account_home
        or rust_root.is_symlink()
        or not rust_root.is_dir()
        or not all(_is_real_executable(executable) for executable in trusted_executables)
        or not python_bin.is_symlink()
        or python_bin_resolved != python_executable
        or environment.get("CFW_RELEASE_RUSTC_EXECUTABLE") != str(rust_bin / "rustc")
        or environment.get("CFW_RELEASE_CARGO_EXECUTABLE") != str(rust_bin / "cargo")
        or environment.get("CFW_RELEASE_POLICY_TOOL_ROOT") != str(policy_tool_root)
        or (
            role != "tool-bootstrap"
            and environment.get("CFW_RELEASE_CARGO_AUDIT_EXECUTABLE")
            != str(cargo_aux_bin / "cargo-audit")
        )
        or (
            role != "tool-bootstrap"
            and environment.get("CFW_RELEASE_CARGO_DENY_EXECUTABLE")
            != str(cargo_aux_bin / "cargo-deny")
        )
        or not _is_real_directory(python_stdlib)
        or python_stdlib
        != python_bin_dir.parent / "lib" / f"python{python_series}"
        or (
            role == "production"
            and (
                validation_python is not None
                or python_bin_dir != production_python_root / "bin"
                or python_executable
                != production_python_root / f"bin/python{python_series}"
                or python_runtime != production_python_root / "Python"
            )
        )
        or (
            role == "unsigned-validation"
            and (
                not validation_python
                or not Path(validation_python).is_absolute()
                or validation_python_resolved != python_executable
            )
        )
        or any(name.startswith("BASH_FUNC_") for name in environment)
        or not required_environment.issubset(environment)
        or not set(environment).issubset(allowed_environment)
        or environment.get("PATH") != expected_path
        or environment.get("LANG") != "C"
        or environment.get("LC_ALL") != "C"
        or environment.get("PYTHONDONTWRITEBYTECODE") != "1"
        or not developer_dir.is_dir()
        or developer_dir.parts[-2:] != ("Contents", "Developer")
    ):
        raise PublicationError("release tool environment does not match the closed contract")
    if role != "tool-bootstrap":
        try:
            expected_cargo_input_root = workspace_input_root(repository, release_home)
            if Path(environment["CFW_RELEASE_CARGO_INPUT_ROOT"]) != expected_cargo_input_root:
                raise ReleaseCargoInputsError(
                    "Cargo workspace input root escaped the release account"
                )
            cargo_inputs = verify_workspace_cargo_inputs(
                repository,
                expected_cargo_input_root,
            )
        except (KeyError, OSError, ReleaseCargoInputsError) as error:
            raise PublicationError(
                "release Cargo workspace inputs do not match the closed contract"
            ) from error
        if (
            environment.get("CFW_RELEASE_CARGO_INPUT_ROOT") != str(cargo_inputs.root)
            or environment.get("CFW_RELEASE_CARGO_VENDOR_ROOT")
            != str(cargo_inputs.vendor)
            or environment.get("CFW_RELEASE_CARGO_LOCK_SHA256")
            != cargo_inputs.cargo_lock_sha256
            or environment.get("CFW_RELEASE_CARGO_VENDOR_SHA256")
            != cargo_inputs.vendor_tree_sha256
        ):
            raise PublicationError(
                "release Cargo workspace input identity differs from its verified tree"
            )
    selected_toolchain_root = environment.get("CFW_TOOLCHAIN_ROOT")
    if selected_toolchain_root is not None and not Path(selected_toolchain_root).is_absolute():
        raise PublicationError("release tool environment has a relative toolchain root")

    environment = {
        name: environment[name]
        for name in required_environment | _OPERATIONAL_ENVIRONMENT
        if name in environment
    }
    xcode_identity = identity_output(
        [APPLE_XCODEBUILD, "-version"], repository, "Xcode", environment
    )
    expected_xcode = (
        f"Xcode {pins['XCODE_VERSION']}; Build version {pins['XCODE_BUILD_VERSION']}"
    )
    if xcode_identity != expected_xcode:
        raise PublicationError(
            f"Xcode identity {xcode_identity!r} does not match {expected_xcode!r}"
        )
    swift_path = Path(
        identity_output(
            [APPLE_XCRUN, "--find", "swift"],
            repository,
            "selected Swift executable",
            environment,
            maximum=4096,
        )
    )
    xcodebuild_path = Path(
        identity_output(
            [APPLE_XCRUN, "--find", "xcodebuild"],
            repository,
            "selected xcodebuild executable",
            environment,
            maximum=4096,
        )
    )
    for executable, label in ((swift_path, "Swift"), (xcodebuild_path, "xcodebuild")):
        if (
            not executable.is_absolute()
            or not executable.is_relative_to(developer_dir)
            or not executable.exists()
            or not os.access(executable, os.X_OK)
        ):
            raise PublicationError(
                f"selected {label} executable is outside the selected Xcode Developer tree"
            )
    return environment


__all__ = [
    "APPLE_SWIFT",
    "APPLE_XCODEBUILD",
    "APPLE_XCRUN",
    "IDENTITY_TIMEOUT_SECONDS",
    "RELEASE_ENVIRONMENT_COMMAND",
    "RELEASE_ENVIRONMENT_SCRIPT",
    "SYSTEM_PATH",
    "identity_output",
    "release_tool_environment",
]
