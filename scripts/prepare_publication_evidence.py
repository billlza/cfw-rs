#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

if __package__:
    from .release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )
    from .release_executor_source import (
        ExecutorSourceError,
        capture_frozen_release_sources,
        require_frozen_sources_unchanged,
    )
    from .publication.common import PublicationError
    from .publication.durable_file import DurabilityOutcomeUnknown
    from .publication.preparer import (
        expected_blocker_report,
        expected_prepared_root,
        expected_review_template,
        expected_signed_app,
        prepare,
        write_review_template,
    )
else:
    from release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )
    from release_executor_source import (
        ExecutorSourceError,
        capture_frozen_release_sources,
        require_frozen_sources_unchanged,
    )
    from publication.common import PublicationError
    from publication.durable_file import DurabilityOutcomeUnknown
    from publication.preparer import (
        expected_blocker_report,
        expected_prepared_root,
        expected_review_template,
        expected_signed_app,
        prepare,
        write_review_template,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Prepare the exact offline 0.4.0 publication closure for legal review."
    )
    commands = result.add_subparsers(dest="command", required=True)
    template = commands.add_parser("review-template")
    template.add_argument("--libbox-source", type=Path, required=True)
    prepare_command = commands.add_parser("prepare")
    prepare_command.add_argument("--libbox-source", type=Path, required=True)
    prepare_command.add_argument("--reviewed-components", type=Path, required=True)
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        require_closed_release_runtime()
        sources = capture_frozen_release_sources(Path(__file__).resolve().parent.parent)
        repository = sources.artifact.repository
        if arguments.command == "review-template":
            output = write_review_template(
                repository=repository,
                libbox_source=arguments.libbox_source,
                output=expected_review_template(repository),
            )
        else:
            output = prepare(
                repository=repository,
                app=expected_signed_app(repository),
                libbox_source=arguments.libbox_source,
                reviewed_components=arguments.reviewed_components,
                output=expected_prepared_root(repository),
            )
        try:
            require_frozen_sources_unchanged(sources)
        except ExecutorSourceError as error:
            raise DurabilityOutcomeUnknown(
                "publication preparation output exists but its source recheck failed; "
                "inspect the retained output before retrying"
            ) from error
    except (PublicationError, ReleasePythonRuntimeError, OSError) as error:
        raise SystemExit(f"error: publication preparation: {error}") from error
    print(f"publication preparation output: {output}")
    if arguments.command == "review-template":
        print(f"publication blocker report: {expected_blocker_report(repository)}")


if __name__ == "__main__":
    main()
