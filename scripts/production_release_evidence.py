#!/usr/bin/env python3
"""Prepare and seal the fixed v0.4.0 production release evidence."""

from __future__ import annotations

import argparse
from pathlib import Path

if __package__:
    from .publication.common import PublicationError
    from .publication.orchestrator import (
        prepare_physical_candidate_manifest,
        seal_production_evidence,
        self_check,
    )
else:
    from publication.common import PublicationError
    from publication.orchestrator import (
        prepare_physical_candidate_manifest,
        seal_production_evidence,
        self_check,
    )


def _repository() -> Path:
    return Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare-physical-candidate-manifest")
    commands.add_parser("seal")
    commands.add_parser("self-check")
    arguments = parser.parse_args()
    try:
        if arguments.command == "prepare-physical-candidate-manifest":
            result = prepare_physical_candidate_manifest(_repository())
            print(
                "physical 40021 candidate artifact-hash manifest prepared: "
                f"{result['sha256']}"
            )
        elif arguments.command == "seal":
            result = seal_production_evidence(_repository())
            print(
                "production release evidence sealed: "
                f"{result['manifest_sha256']}"
            )
        else:
            self_check(_repository())
            print("production release evidence orchestrator self-check passed")
    except (OSError, PublicationError, ValueError) as error:
        raise SystemExit(f"error: production release evidence: {error}") from error


if __name__ == "__main__":
    main()
