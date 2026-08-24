#!/usr/bin/env python3
"""Fresh-process child for the real pinned updater-signer integration test."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY))
launcher = importlib.import_module("scripts.updater_signing_launcher")


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("error: integration child requires HOME and archive paths", file=sys.stderr)
        return 2
    home = Path(argv[0])
    archive = Path(argv[1])
    password = bytearray(sys.stdin.buffer.read(launcher.MAX_PASSWORD_BYTES + 1))
    if not password or len(password) > launcher.MAX_PASSWORD_BYTES:
        _wipe(password)
        print("error: integration password is outside its bound", file=sys.stderr)
        return 2
    try:
        launcher.launch_updater_signer(
            archive,
            home=home,
            password_reader=lambda: password,
            acl_checker=lambda _path: None,
        )
    except launcher.UpdaterSigningLaunchError as error:
        print(f"error: updater signer integration failed closed: {error}", file=sys.stderr)
        return 1
    finally:
        _wipe(password)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
