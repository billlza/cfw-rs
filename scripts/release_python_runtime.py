"""Runtime admission for Python CLIs that can create production release evidence."""

from __future__ import annotations

import os
import hashlib
from pathlib import Path
import pwd
import re
import sys
import sysconfig


class ReleasePythonRuntimeError(RuntimeError):
    """The CLI was not launched through the closed release Python boundary."""


_PYTHON_VERSION_RE = re.compile(r"3[.][0-9]+[.][0-9]+")
_RUST_VERSION_RE = re.compile(r"[1-9][0-9]*[.][0-9]+[.][0-9]+")
_TOOL_VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)[.][0-9]+[.][0-9]+")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN_ENVIRONMENT = frozenset(
    {
        "BASH_ENV",
        "BASH_COMPAT",
        "CARGO",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "CDPATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "ENV",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
        "GLOBIGNORE",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "NODE_PATH",
        "NPM_CONFIG_USERCONFIG",
        "POSIXLY_CORRECT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "SDKROOT",
        "SWIFT_EXEC",
        "SWIFT_DRIVER_CLANG_EXEC",
        "SWIFT_DRIVER_SWIFT_EXEC",
        "SWIFT_DRIVER_SWIFT_FRONTEND_EXEC",
        "SWIFT_DRIVER_TOOLCHAIN_PATH",
        "SWIFT_DRIVER_USE_FRONTEND_PATH",
        "TOOLCHAINS",
        "XCODE_XCCONFIG_FILE",
        "CFW_UNSIGNED_VALIDATION_PYTHON",
    }
)


def _pinned_versions(repository: Path) -> tuple[str, str, str, str]:
    pins_path = repository / "scripts/dependency_pins.env"
    try:
        data = pins_path.read_bytes()
    except OSError as error:
        raise ReleasePythonRuntimeError(
            "production release Python pins cannot be read"
        ) from error
    if not data or len(data) > 64 * 1024:
        raise ReleasePythonRuntimeError(
            "production release Python pins are not bounded"
        )
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ReleasePythonRuntimeError(
            "production release Python pins are not UTF-8"
        ) from error
    python_versions = [
        line.removeprefix("PYTHON_VERSION=")
        for line in lines
        if line.startswith("PYTHON_VERSION=")
    ]
    rust_versions = [
        line.removeprefix("RUST_VERSION=")
        for line in lines
        if line.startswith("RUST_VERSION=")
    ]
    cargo_audit_versions = [
        line.removeprefix("CARGO_AUDIT_VERSION=")
        for line in lines
        if line.startswith("CARGO_AUDIT_VERSION=")
    ]
    cargo_deny_versions = [
        line.removeprefix("CARGO_DENY_VERSION=")
        for line in lines
        if line.startswith("CARGO_DENY_VERSION=")
    ]
    if (
        len(python_versions) != 1
        or _PYTHON_VERSION_RE.fullmatch(python_versions[0]) is None
    ):
        raise ReleasePythonRuntimeError(
            "production release Python version is not pinned exactly"
        )
    if (
        len(rust_versions) != 1
        or _RUST_VERSION_RE.fullmatch(rust_versions[0]) is None
    ):
        raise ReleasePythonRuntimeError(
            "production release Rust version is not pinned exactly"
        )
    for label, values in (
        ("cargo-audit", cargo_audit_versions),
        ("cargo-deny", cargo_deny_versions),
    ):
        if len(values) != 1 or _TOOL_VERSION_RE.fullmatch(values[0]) is None:
            raise ReleasePythonRuntimeError(
                f"production release {label} version is not pinned exactly"
            )
    return (
        python_versions[0],
        rust_versions[0],
        cargo_audit_versions[0],
        cargo_deny_versions[0],
    )


def require_closed_release_runtime(*, allow_unsigned_validation: bool = False) -> None:
    repository = Path(__file__).resolve().parent.parent
    version, rust_version, cargo_audit_version, cargo_deny_version = (
        _pinned_versions(repository)
    )
    if sys.version_info[:3] != tuple(int(part) for part in version.split(".")):
        raise ReleasePythonRuntimeError(
            "production release Python requires the closed isolated launcher"
        )
    # Import toolchain parsers only after the selected Python version is admitted.
    if __package__:
        from .release_rust_toolchain import (
            ReleaseRustToolchainError,
            selected_toolchain_root,
        )
    else:
        from release_rust_toolchain import (
            ReleaseRustToolchainError,
            selected_toolchain_root,
        )
    series = version.rsplit(".", 1)[0]
    try:
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve(strict=True)
    except (KeyError, OSError) as error:
        raise ReleasePythonRuntimeError(
            "production release account identity cannot be resolved"
        ) from error
    validation_launcher_value = os.environ.get("CFW_UNSIGNED_VALIDATION_PYTHON")
    if validation_launcher_value is not None:
        if not allow_unsigned_validation:
            raise ReleasePythonRuntimeError(
                "production release Python refuses unsigned-validation admission"
            )
        validation_launcher = Path(validation_launcher_value)
        if not validation_launcher.is_absolute():
            raise ReleasePythonRuntimeError(
                "unsigned-validation Python launcher is not absolute"
            )
        try:
            expected_executable = validation_launcher.resolve(strict=True)
            expected_root = validation_launcher.parent.parent.resolve(strict=True)
        except OSError as error:
            raise ReleasePythonRuntimeError(
                "unsigned-validation Python identity cannot be resolved"
            ) from error
    else:
        expected_root = Path(
            f"/opt/homebrew/Cellar/python@{series}/{version}/Frameworks/"
            f"Python.framework/Versions/{series}"
        )
        expected_executable = expected_root / "bin" / f"python{series}"
    expected_runtime = expected_root / "Python"
    expected_stdlib = expected_root / "lib" / f"python{series}"
    try:
        expected_rust_bin = selected_toolchain_root(
            account_home, rust_version, os.environ["CFW_RELEASE_RUST_TOOLCHAIN"]
        ) / "bin"
    except (KeyError, ReleaseRustToolchainError) as error:
        raise ReleasePythonRuntimeError(
            "production release Rust toolchain selection is missing or invalid"
        ) from error
    policy_bin = (
        account_home
        / ".cfm-release-tooling"
        / f"policy-{cargo_audit_version}-{cargo_deny_version}"
        / "bin"
    )
    expected_path = ":".join(
        (
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
            str(expected_rust_bin),
            str(policy_bin),
        )
    )
    try:
        cargo_lock_sha256 = hashlib.sha256(
            (repository / "Cargo.lock").read_bytes()
        ).hexdigest()
    except OSError as error:
        raise ReleasePythonRuntimeError(
            "production release Cargo.lock identity cannot be resolved"
        ) from error
    cargo_input_root = (
        account_home
        / ".cfm-release-tooling"
        / f"cargo-workspace-{cargo_lock_sha256}"
    )
    cargo_vendor_root = cargo_input_root / "verified-vendor"
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or not sys.dont_write_bytecode
        or sys.warnoptions != ["error"]
        or os.environ.get("PYTHONDONTWRITEBYTECODE") != "1"
        or os.environ.get("HOME") != str(account_home)
        or os.environ.get("PATH") != expected_path
        or os.environ.get("CFW_RELEASE_RUSTC_EXECUTABLE") != str(expected_rust_bin / "rustc")
        or os.environ.get("CFW_RELEASE_CARGO_EXECUTABLE") != str(expected_rust_bin / "cargo")
        or os.environ.get("LANG") != "C"
        or os.environ.get("LC_ALL") != "C"
        or os.environ.get("CFW_RELEASE_PYTHON_EXECUTABLE")
        != str(expected_executable)
        or os.environ.get("CFW_RELEASE_PYTHON_RUNTIME") != str(expected_runtime)
        or os.environ.get("CFW_RELEASE_PYTHON_STDLIB") != str(expected_stdlib)
        or os.environ.get("CFW_RELEASE_POLICY_TOOL_ROOT")
        != str(policy_bin.parent)
        or os.environ.get("CFW_RELEASE_CARGO_INPUT_ROOT") != str(cargo_input_root)
        or os.environ.get("CFW_RELEASE_CARGO_VENDOR_ROOT") != str(cargo_vendor_root)
        or os.environ.get("CFW_RELEASE_CARGO_LOCK_SHA256") != cargo_lock_sha256
        or _SHA256_RE.fullmatch(
            os.environ.get("CFW_RELEASE_CARGO_VENDOR_SHA256", "")
        )
        is None
    ):
        raise ReleasePythonRuntimeError(
            "production release Python requires the closed isolated launcher"
        )
    try:
        executable = Path(sys.executable).resolve(strict=True)
        selected_executable = expected_executable.resolve(strict=True)
        runtime = (Path(sys.base_prefix) / "Python").resolve(strict=True)
        selected_runtime = expected_runtime.resolve(strict=True)
        stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
        selected_stdlib = expected_stdlib.resolve(strict=True)
    except OSError as error:
        raise ReleasePythonRuntimeError(
            "production release Python identity cannot be resolved"
        ) from error
    if (
        executable != selected_executable
        or runtime != selected_runtime
        or stdlib != selected_stdlib
    ):
        raise ReleasePythonRuntimeError(
            "production release Python differs from the closed tool identity"
        )
    for name in os.environ:
        if (
            name in _FORBIDDEN_ENVIRONMENT
            and not (
                name == "CFW_UNSIGNED_VALIDATION_PYTHON"
                and allow_unsigned_validation
                and validation_launcher_value is not None
            )
        ) or name.startswith("BASH_FUNC_"):
            raise ReleasePythonRuntimeError(
                f"production release Python refuses ambient {name}"
            )


__all__ = ["ReleasePythonRuntimeError", "require_closed_release_runtime"]
