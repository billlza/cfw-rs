#!/usr/bin/env python3
"""Generate and validate the final-candidate notarization/installed binding.

This is the CLI front end for ``publication.final_candidate`` (Task 12.2). It
extends the existing offline publication tooling; it consumes the wave-11
physical-evidence aggregate and the path/name-only updater-key blocker, never
opens the workspace updater key, and never fabricates acceptance. When
notarization, staple, Gatekeeper, or the physical evidence is unavailable, or an
updater-key file is present in the workspace, the produced binding is
environment-gated to ``blocked`` and ``validate --require-verified`` fails
closed.

Usage:
    final_candidate_binding.py build --request request.json --output binding.json [--fixture]
    final_candidate_binding.py validate --binding binding.json [--fixture] [--require-verified]
    final_candidate_binding.py status [--evidence-dir DIR] [--strict]

``status`` reports, without fabricating anything, which environment-gated inputs
exist (``present``/``not-run``) and which updater-key files block release
(path/name only). With ``--strict`` a blocked candidate exits nonzero.
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
from publication.final_candidate import (
    build_final_candidate_binding,
    environment_status,
    validate_final_candidate_binding,
)


def _repository() -> Path:
    return Path(__file__).resolve().parent.parent


def command_build(arguments: argparse.Namespace) -> None:
    request = load_json(arguments.request.resolve(strict=True))
    binding = build_final_candidate_binding(
        _repository(), request, fixture=arguments.fixture
    )
    output = arguments.output
    if output.exists() or output.is_symlink():
        raise PublicationError(f"refusing to replace final candidate binding: {output}")
    write_new(output, canonical_json(binding))
    print(
        f"final candidate binding written: {output.resolve(strict=True)} "
        f"status={binding['status']} blocked={binding['blocked_inputs']}"
    )


def command_status(arguments: argparse.Namespace) -> None:
    report = environment_status(
        _repository(),
        evidence_directory=arguments.evidence_dir.resolve() if arguments.evidence_dir else None,
    )
    print(f"final candidate inputs under {report['evidence_directory']}")
    for name in sorted(report["inputs"]):
        entry = report["inputs"][name]
        print(f"  {name}: {entry['state']} ({entry['path']})")
    for block in report["updater_key_blocks"]:
        # Path and name only; the key is never opened (Requirement 8.1).
        print(
            f"  updater-key release blocker: {block['path']} (name={block['name']}) "
            f"relocate to {block['relocation_target']}; "
            f"rotation_required={block['rotation_required']} "
            f"trust_migration_required={block['trust_migration_required']}"
        )
    print(
        f"final candidate status: {report['status']} blocked={report['blocked_inputs']}"
    )
    if arguments.strict and report["status"] != "inputs-present":
        raise PublicationError(
            "final candidate is blocked under strict validation: "
            f"{report['blocked_inputs']}"
        )


def command_validate(arguments: argparse.Namespace) -> None:
    binding = load_json(arguments.binding.resolve(strict=True))
    result = validate_final_candidate_binding(
        _repository(),
        binding,
        fixture=arguments.fixture,
        require_verified=arguments.require_verified,
    )
    print(
        f"final candidate binding verified: status={result['status']} "
        f"blocked={result['blocked_inputs']}"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    build_command = commands.add_parser("build")
    build_command.add_argument("--request", type=Path, required=True)
    build_command.add_argument("--output", type=Path, required=True)
    build_command.add_argument("--fixture", action="store_true")
    build_command.set_defaults(handler=command_build)
    validate_command = commands.add_parser("validate")
    validate_command.add_argument("--binding", type=Path, required=True)
    validate_command.add_argument("--fixture", action="store_true")
    validate_command.add_argument("--require-verified", action="store_true")
    validate_command.set_defaults(handler=command_validate)
    status_command = commands.add_parser("status")
    status_command.add_argument("--evidence-dir", type=Path, default=None)
    status_command.add_argument("--strict", action="store_true")
    status_command.set_defaults(handler=command_status)
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        arguments.handler(arguments)
    except (PublicationError, OSError) as error:
        raise SystemExit(f"error: final candidate binding: {error}") from error


if __name__ == "__main__":
    main()
