#!/usr/bin/env python3
"""Seal or verify the three fixed v0.4.0 GA release stages."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

if __package__:
    from .release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )
    from .publication.common import PublicationError, canonical_json, sha256_bytes
else:
    from release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )
    from publication.common import PublicationError, canonical_json, sha256_bytes


STAGES = ("prepackage", "ga-acceptance", "publication")
RETIRED_COMMANDS = frozenset(
    {
        "prepare-physical-candidate-manifest",
        "seal",
        "validation",
        "final",
    }
)


def _repository() -> Path:
    return Path(__file__).resolve().parent.parent


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    arguments = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description=__doc__)
    if arguments and arguments[0] in RETIRED_COMMANDS:
        parser.error(
            f"{arguments[0]} is retired; use prepackage, ga-acceptance, or publication"
        )
    commands = parser.add_subparsers(dest="command", required=True)
    for stage in STAGES:
        commands.add_parser(stage)
    verify = commands.add_parser("verify")
    verify.add_argument("stage", choices=STAGES)
    commands.add_parser("self-check")
    return parser.parse_args(arguments)


def main() -> None:
    arguments = _arguments()
    source_only_self_check = sys.argv[1:] == ["self-check"]
    if not source_only_self_check:
        try:
            require_closed_release_runtime()
        except ReleasePythonRuntimeError as error:
            raise SystemExit(f"error: production release evidence: {error}") from error

    if __package__:
        from .publication.orchestrator import (
            seal_ga_acceptance,
            seal_prepackage,
            seal_publication,
        )
        from .publication.ga_release_contract import self_check, verify_stage
    else:
        from publication.orchestrator import (
            seal_ga_acceptance,
            seal_prepackage,
            seal_publication,
        )
        from publication.ga_release_contract import self_check, verify_stage

    repository = _repository()
    try:
        if arguments.command == "prepackage":
            manifest = seal_prepackage(repository)
        elif arguments.command == "ga-acceptance":
            manifest = seal_ga_acceptance(repository)
        elif arguments.command == "publication":
            manifest = seal_publication(repository)
        elif arguments.command == "verify":
            manifest = verify_stage(repository, arguments.stage)
        else:
            self_check(repository)
            print("production GA three-stage orchestrator self-check passed")
            return
    except (OSError, PublicationError, ValueError) as error:
        raise SystemExit(f"error: production release evidence: {error}") from error
    print(
        f"{manifest['stage']} GA seal verified: "
        f"{sha256_bytes(canonical_json(manifest))}"
    )


if __name__ == "__main__":
    main()
