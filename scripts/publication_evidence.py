#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
if __package__:
    from .release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )
    from .publication.common import PublicationError
    from .publication.draft import draft
    from .publication.durable_file import DurabilityOutcomeUnknown
    from .publication.finalize import finalize
    from .publication.verify import verify
    from .release_executor_source import (
        ExecutorSourceError,
        capture_frozen_release_sources,
        require_frozen_sources_unchanged,
    )
else:
    from release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )
    from publication.common import PublicationError
    from publication.draft import draft
    from publication.durable_file import DurabilityOutcomeUnknown
    from publication.finalize import finalize
    from publication.verify import verify
    from release_executor_source import (
        ExecutorSourceError,
        capture_frozen_release_sources,
        require_frozen_sources_unchanged,
    )


def command_draft(arguments: argparse.Namespace, *, repository: Path | None) -> str:
    return draft(
        arguments.prepared, arguments.app, arguments.output, arguments.fixture,
        repository=repository,
    )


def command_finalize(arguments: argparse.Namespace, *, repository: Path | None) -> None:
    finalize(
        arguments.prepared,
        arguments.app,
        arguments.review,
        arguments.output,
        arguments.fixture,
        repository=repository,
    )


def command_verify(arguments: argparse.Namespace, *, repository: Path | None) -> str:
    verify(
        arguments.evidence, arguments.app, arguments.fixture, repository=repository
    )
    return f"publication evidence verified: {arguments.evidence.resolve(strict=True)}"


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
        sources = None
        if not arguments.fixture:
            require_closed_release_runtime()
            sources = capture_frozen_release_sources(Path(__file__).resolve().parent.parent)
        message = arguments.handler(
            arguments,
            repository=None if sources is None else sources.artifact.repository,
        )
        if sources is not None:
            try:
                require_frozen_sources_unchanged(sources)
            except ExecutorSourceError as error:
                if arguments.command == "verify":
                    raise
                raise DurabilityOutcomeUnknown(
                    "publication output exists but its source recheck failed; "
                    "inspect the retained output before retrying"
                ) from error
    except (PublicationError, ReleasePythonRuntimeError, OSError) as error:
        raise SystemExit(f"error: publication evidence: {error}") from error
    if message is not None:
        print(message)


if __name__ == "__main__":
    main()
