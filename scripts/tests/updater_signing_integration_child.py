#!/usr/bin/env python3
"""Fresh-process child for the real pinned updater-signer integration test."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import sys


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY))
launcher = importlib.import_module("scripts.updater_signing_launcher")
runtime_admission = importlib.import_module("scripts.release_python_runtime")


def _closed_unsigned_validation_runtime() -> Path:
    validation_value = os.environ.get("CFW_UNSIGNED_VALIDATION_PYTHON")
    selected_value = os.environ.get("CFW_RELEASE_PYTHON_EXECUTABLE")
    if not validation_value or not selected_value:
        raise launcher.UpdaterSigningLaunchError(
            "unsigned-validation integration requires both Python selectors"
        )
    validation = Path(validation_value)
    selected = Path(selected_value)
    if not validation.is_absolute() or not selected.is_absolute():
        raise launcher.UpdaterSigningLaunchError(
            "unsigned-validation Python selectors must be absolute"
        )
    try:
        canonical_validation = validation.resolve(strict=True)
        canonical_selected = selected.resolve(strict=True)
        canonical_running = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise launcher.UpdaterSigningLaunchError(
            "unsigned-validation Python selectors cannot be resolved"
        ) from error
    if not (
        canonical_validation == canonical_selected == canonical_running
    ):
        raise launcher.UpdaterSigningLaunchError(
            "unsigned-validation Python selectors do not identify the running "
            "runtime"
        )
    try:
        runtime_admission.require_closed_release_runtime(
            allow_unsigned_validation=True
        )
    except runtime_admission.ReleasePythonRuntimeError as error:
        raise launcher.UpdaterSigningLaunchError(
            "unsigned-validation Python did not pass closed runtime admission"
        ) from error
    return canonical_running


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _read_bounded_password() -> bytearray:
    password = bytearray(
        sys.stdin.buffer.read(launcher.MAX_PASSWORD_BYTES + 1)
    )
    if not password or len(password) > launcher.MAX_PASSWORD_BYTES:
        _wipe(password)
        raise launcher.UpdaterSigningLaunchError(
            "integration password is outside its bound"
        )
    return password


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[2] not in {"production", "unsigned-validation"}:
        print(
            "error: integration child requires HOME, archive, and role",
            file=sys.stderr,
        )
        return 2
    home = Path(argv[0])
    archive = Path(argv[1])
    role = argv[2]
    validation_runtime: Path | None = None
    try:
        if role == "unsigned-validation":
            validation_runtime = _closed_unsigned_validation_runtime()
        elif "CFW_UNSIGNED_VALIDATION_PYTHON" in os.environ:
            raise launcher.UpdaterSigningLaunchError(
                "production integration role refuses unsigned-validation Python"
            )
    except launcher.UpdaterSigningLaunchError as error:
        print(
            f"error: updater signer integration failed closed: {error}",
            file=sys.stderr,
        )
        return 1
    try:
        if role == "unsigned-validation":
            if validation_runtime is None:
                raise launcher.UpdaterSigningLaunchError(
                    "unsigned-validation runtime admission was not retained"
                )

            def signer_verifier(repository: Path) -> launcher.HeldSigner:
                return launcher._verify_pinned_tauri_signer_with_runtime(
                    repository,
                    validation_runtime,
                )

            launcher._launch_updater_signer(
                archive,
                signer_verifier=signer_verifier,
                home=home,
                password_reader=_read_bounded_password,
                acl_checker=lambda _path: None,
            )
        else:
            launcher.launch_updater_signer(
                archive,
                home=home,
                password_reader=_read_bounded_password,
                acl_checker=lambda _path: None,
            )
    except launcher.UpdaterSigningLaunchError as error:
        print(f"error: updater signer integration failed closed: {error}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
