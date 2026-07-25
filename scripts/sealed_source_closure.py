#!/usr/bin/env python3
"""Generate and validate the sealed source/license/vulnerability/SBOM closure.

This is the CLI front end for ``publication.sealed_closure`` (Task 12.1). It
extends the existing offline publication tooling; it never reads the workspace
updater key and never fabricates acceptance. When the signed app tree, the
libbox XCFramework, or the govulncheck reports are unavailable, the produced
closure is environment-gated to ``blocked`` and ``validate --require-sealed``
fails closed.

Usage:
    sealed_source_closure.py build --request request.json --output closure.json [--fixture]
    sealed_source_closure.py validate --closure closure.json [--fixture] [--require-sealed]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from publication.common import (
    PublicationError,
    canonical_json,
    load_json,
    write_new,
)
from publication.sealed_closure import build_sealed_closure, validate_sealed_closure


def _repository() -> Path:
    return Path(__file__).resolve().parent.parent


def command_build(arguments: argparse.Namespace) -> None:
    request = load_json(arguments.request.resolve(strict=True))
    closure = build_sealed_closure(_repository(), request, fixture=arguments.fixture)
    output = arguments.output
    if output.exists() or output.is_symlink():
        raise PublicationError(f"refusing to replace sealed closure: {output}")
    write_new(output, canonical_json(closure))
    print(f"sealed closure written: {output.resolve(strict=True)} status={closure['status']}")


def command_validate(arguments: argparse.Namespace) -> None:
    closure = load_json(arguments.closure.resolve(strict=True))
    result = validate_sealed_closure(
        _repository(),
        closure,
        fixture=arguments.fixture,
        require_sealed=arguments.require_sealed,
    )
    print(f"sealed closure verified: status={result['status']} blocked={result['blocked_inputs']}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    build_command = commands.add_parser("build")
    build_command.add_argument("--request", type=Path, required=True)
    build_command.add_argument("--output", type=Path, required=True)
    build_command.add_argument("--fixture", action="store_true")
    build_command.set_defaults(handler=command_build)
    validate_command = commands.add_parser("validate")
    validate_command.add_argument("--closure", type=Path, required=True)
    validate_command.add_argument("--fixture", action="store_true")
    validate_command.add_argument("--require-sealed", action="store_true")
    validate_command.set_defaults(handler=command_validate)
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        arguments.handler(arguments)
    except (PublicationError, OSError) as error:
        raise SystemExit(f"error: sealed source closure: {error}") from error


if __name__ == "__main__":
    main()
