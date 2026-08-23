#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from release_python_runtime import (
    ReleasePythonRuntimeError,
    require_closed_release_runtime,
)

if "--fixture" not in sys.argv[1:]:
    try:
        require_closed_release_runtime()
    except ReleasePythonRuntimeError as error:
        raise SystemExit(f"error: publication evidence: {error}") from error

from publication.common import PublicationError
from publication.draft import draft
from publication.finalize import finalize
from publication.verify import verify


def command_draft(arguments: argparse.Namespace) -> None:
    print(draft(arguments.prepared, arguments.app, arguments.output, arguments.fixture))


def command_finalize(arguments: argparse.Namespace) -> None:
    finalize(
        arguments.prepared,
        arguments.app,
        arguments.review,
        arguments.output,
        arguments.fixture,
    )


def command_verify(arguments: argparse.Namespace) -> None:
    verify(arguments.evidence, arguments.app, arguments.fixture)
    print(f"publication evidence verified: {arguments.evidence.resolve(strict=True)}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    draft_command = commands.add_parser("draft")
    draft_command.add_argument("--prepared", type=Path, required=True)
    draft_command.add_argument("--app", type=Path, required=True)
    draft_command.add_argument("--output", type=Path, required=True)
    draft_command.add_argument("--fixture", action="store_true")
    draft_command.set_defaults(handler=command_draft)
    finalize_command = commands.add_parser("finalize")
    finalize_command.add_argument("--prepared", type=Path, required=True)
    finalize_command.add_argument("--app", type=Path, required=True)
    finalize_command.add_argument("--review", type=Path, required=True)
    finalize_command.add_argument("--output", type=Path, required=True)
    finalize_command.add_argument("--fixture", action="store_true")
    finalize_command.set_defaults(handler=command_finalize)
    verify_command = commands.add_parser("verify")
    verify_command.add_argument("--evidence", type=Path, required=True)
    verify_command.add_argument("--app", type=Path, required=True)
    verify_command.add_argument("--fixture", action="store_true")
    verify_command.set_defaults(handler=command_verify)
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        arguments.handler(arguments)
    except (PublicationError, OSError) as error:
        raise SystemExit(f"error: publication evidence: {error}") from error


if __name__ == "__main__":
    main()
