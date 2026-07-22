#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from publication.common import PublicationError
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
    repository = Path(__file__).resolve().parent.parent
    arguments = parser().parse_args()
    try:
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
    except (PublicationError, OSError) as error:
        raise SystemExit(f"error: publication preparation: {error}") from error
    print(f"publication preparation output: {output}")
    if arguments.command == "review-template":
        print(f"publication blocker report: {expected_blocker_report(repository)}")


if __name__ == "__main__":
    main()
