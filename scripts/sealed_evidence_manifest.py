#!/usr/bin/env python3
"""Seal and verify the immutable outer Evidence Manifest and publication gate.

This is the CLI front end for ``publication.sealed_manifest`` (Task 12.3). It
extends the existing offline release tooling and composes, as black boxes, the
P0 source/boundary gates, the deterministic unsigned-CI lanes, the wave-11
physical/signed-installed aggregate, the task-12.1 sealed source/license/
vulnerability/SBOM closure, the task-12.2 final-candidate notarization/installed
binding, and the path/name-only updater-key release blocker.

The seal is immutable: ``seal`` refuses to overwrite an existing manifest, and
``verify`` re-derives every derived field so a hand-edited manifest is rejected.
Publication is fail closed: ``publication-gate`` permits creating publication
artifacts only when every gate passes and every capability has reached
``Sealed_Release_Evidence``. There is no override flag and no fallback; an
unavailable input is reported ``not-run`` and keeps publication refused. The
workspace updater key is referenced by path and name only and is never opened.

Usage:
    sealed_evidence_manifest.py collect-source-gates --output p0-source-gates.json
    sealed_evidence_manifest.py ci-toolchain-binding
    sealed_evidence_manifest.py collect-ci-lanes --output unsigned-ci-lanes.json
    sealed_evidence_manifest.py seal --request request.json --output manifest.json [--fixture]
    sealed_evidence_manifest.py verify --manifest manifest.json [--fixture] [--require-sealed]
    sealed_evidence_manifest.py publication-gate [--manifest manifest.json] [--fixture]
    sealed_evidence_manifest.py status [--evidence-dir DIR]
    sealed_evidence_manifest.py self-check
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path

from publication.ci_lanes import (
    DEFAULT_LIBBOX_OUTPUT,
    DEFAULT_LIBBOX_SOURCE_TEMPLATE,
    LANES,
    collect_ci_lanes,
    derive_toolchain_binding,
)
from publication.common import PublicationError, canonical_json, write_new
from publication.sealed_manifest import (
    DEFAULT_MANIFEST_PATH,
    GATE_ORDER,
    REQUIRED_SOURCE_GATES,
    authorize_publication_artifacts,
    build_sealed_evidence_manifest,
    environment_status,
    load_sealed_manifest,
    seal_manifest,
    self_check,
    validate_sealed_evidence_manifest,
)

# The fixed per-gate wall-clock bound. A gate that exceeds it is recorded as
# ``timeout`` - a non-passing result - and is never masked into a pass.
GATE_TIMEOUT_SECONDS = 900


def _repository() -> Path:
    return Path(__file__).resolve().parent.parent


def _commit(repository: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise PublicationError("cannot resolve the repository commit for the sealed manifest")
    return result.stdout.strip()


def command_collect_source_gates(arguments: argparse.Namespace) -> None:
    """Run the repository P0 source/boundary gates and record their exact results.

    Each gate's combined output is content-addressed and its real exit status is
    recorded. A nonzero exit, a timeout, or a missing gate script is recorded as
    a non-passing result; nothing is converted into success.
    """
    repository = _repository()
    commit = _commit(repository)
    gates = []
    for identifier in sorted(REQUIRED_SOURCE_GATES):
        script = REQUIRED_SOURCE_GATES[identifier]
        path = repository / script
        if path.is_symlink() or not path.is_file():
            raise PublicationError(f"p0 source gate script is missing: {script}")
        command = (
            ["bash", str(path)]
            if script.endswith(".sh")
            else ["python3", "-B", str(path)]
        )
        try:
            completed = subprocess.run(
                command,
                cwd=str(repository),
                capture_output=True,
                check=False,
                timeout=GATE_TIMEOUT_SECONDS,
            )
            output = completed.stdout + completed.stderr
            exit_code = completed.returncode
            status = "passed" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired as error:
            output = (error.stdout or b"") + (error.stderr or b"")
            exit_code = 124
            status = "timeout"
        if exit_code < 0 or exit_code > 255:
            exit_code = 255
            status = "failed"
        gates.append(
            {
                "id": identifier,
                "script": script,
                "status": status,
                "exit_code": exit_code,
                "log_sha256": hashlib.sha256(output).hexdigest(),
                "commit": commit,
            }
        )
    document = {"gates": gates}
    output_path = arguments.output
    if output_path.exists() or output_path.is_symlink():
        raise PublicationError(f"refusing to replace a source gate record: {output_path}")
    write_new(output_path, canonical_json(document))
    failed = [gate["id"] for gate in gates if gate["status"] != "passed"]
    print(
        f"p0 source gate record written: {output_path.resolve(strict=True)} "
        f"gates={len(gates)} failed={failed}"
    )


def command_ci_toolchain_binding(_arguments: argparse.Namespace) -> None:
    """Print the single toolchain binding the unsigned-CI lanes are bound to."""
    digest, identity = derive_toolchain_binding(_repository())
    print(canonical_json(identity).decode("utf-8"), end="")
    print(f"toolchain_sha256: {digest}")


def command_collect_ci_lanes(arguments: argparse.Namespace) -> None:
    """Run the required unsigned-CI lanes and record their exact results.

    Each lane's combined output is content-addressed and its real exit status is
    recorded, bound to one commit and one toolchain digest. A nonzero exit is
    ``failed``, exceeding the lane's wall-clock bound is ``timeout``, and neither
    can be written as ``passed``.
    """
    repository = _repository()
    result = collect_ci_lanes(
        repository,
        commit=_commit(repository),
        output=arguments.output,
        journal=(
            arguments.output.parent / "ci-lane-journal"
            if arguments.journal is None
            else arguments.journal
        ),
        only=frozenset(arguments.only or ()),
        rerun=frozenset(arguments.rerun or ()),
        assemble_only=arguments.assemble_only,
        libbox_source=arguments.libbox_source,
        libbox_output=arguments.libbox_output,
    )
    for lane in result["document"]["lanes"]:
        print(f"  lane {lane['id']}: {lane['status']} (exit {lane['exit_code']})")
    print(
        f"unsigned CI lane record: {Path(result['output']).resolve(strict=True)} "
        f"toolchain_sha256={result['toolchain_sha256']} failed={result['failures']}"
    )
    if result["failures"]:
        # The record is written exactly as observed; the gate refuses it.
        raise SystemExit(
            f"error: sealed evidence manifest: unsigned CI lanes did not pass: {result['failures']}"
        )


def command_seal(arguments: argparse.Namespace) -> None:
    request = load_sealed_manifest(arguments.request.resolve(strict=True))
    manifest = build_sealed_evidence_manifest(
        _repository(), request, fixture=arguments.fixture
    )
    seal_manifest(arguments.output, manifest)
    print(
        f"sealed evidence manifest written: {arguments.output.resolve(strict=True)} "
        f"status={manifest['status']} blocked={manifest['blocked_inputs']}"
    )
    for name in GATE_ORDER:
        print(f"  gate {name}: {manifest['gates'][name]['status']}")
    for capability in manifest["capabilities"]:
        print(f"  capability {capability['id']}: {capability['highest_level']}")
    decision = manifest["publication"]
    print(
        f"publication artifacts permitted: {decision['artifacts_permitted']} "
        f"refusals={decision['refusals']}"
    )


def command_verify(arguments: argparse.Namespace) -> None:
    document = load_sealed_manifest(arguments.manifest.resolve(strict=True))
    result = validate_sealed_evidence_manifest(
        _repository(),
        document,
        fixture=arguments.fixture,
        require_sealed=arguments.require_sealed,
    )
    print(
        f"sealed evidence manifest verified: status={result['status']} "
        f"blocked={result['blocked_inputs']} "
        f"publication={result['publication']['artifacts_permitted']}"
    )


def command_publication_gate(arguments: argparse.Namespace) -> None:
    repository = _repository()
    manifest_path = (
        repository / DEFAULT_MANIFEST_PATH if arguments.manifest is None else arguments.manifest
    )
    if manifest_path.is_symlink() or not manifest_path.is_file():
        # Absence is never success: without a sealed manifest, publication
        # artifacts may not be created.
        raise PublicationError(
            f"publication is blocked: no sealed Evidence Manifest at {manifest_path}"
        )
    document = load_sealed_manifest(manifest_path.resolve(strict=True))
    result = authorize_publication_artifacts(
        repository, document, fixture=arguments.fixture
    )
    print(
        "publication artifacts authorized by the sealed Evidence Manifest: "
        f"{result['bindings']['final_candidate_sha256']}"
    )


def command_status(arguments: argparse.Namespace) -> None:
    report = environment_status(
        _repository(),
        evidence_directory=arguments.evidence_dir.resolve() if arguments.evidence_dir else None,
    )
    print(f"sealed manifest inputs under {report['evidence_directory']}")
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
    print(f"  sealed manifest: {report['manifest_state']} ({report['manifest_path']})")
    print(f"sealed manifest status: {report['status']} blocked={report['blocked_inputs']}")


def command_self_check(_arguments: argparse.Namespace) -> None:
    self_check()
    print("sealed outer evidence manifest self-check ok")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect-source-gates")
    collect.add_argument("--output", type=Path, required=True)
    collect.set_defaults(handler=command_collect_source_gates)
    binding = commands.add_parser("ci-toolchain-binding")
    binding.set_defaults(handler=command_ci_toolchain_binding)
    lanes = commands.add_parser("collect-ci-lanes")
    lanes.add_argument("--output", type=Path, required=True)
    lanes.add_argument("--journal", type=Path, default=None)
    lanes.add_argument(
        "--only",
        action="append",
        choices=sorted(lane.identifier for lane in LANES),
        help="run only these lanes; every other lane must already be recorded",
    )
    lanes.add_argument(
        "--rerun",
        action="append",
        choices=sorted(lane.identifier for lane in LANES),
        help="re-run these lanes even when they are already recorded",
    )
    lanes.add_argument(
        "--assemble-only",
        action="store_true",
        help="assemble the document from recorded lanes without running anything",
    )
    lanes.add_argument(
        "--libbox-source",
        type=Path,
        default=None,
        help=f"patched sing-box tree (default: {DEFAULT_LIBBOX_SOURCE_TEMPLATE})",
    )
    lanes.add_argument(
        "--libbox-output",
        type=Path,
        default=None,
        help=f"libbox build lane output (default: {DEFAULT_LIBBOX_OUTPUT})",
    )
    lanes.set_defaults(handler=command_collect_ci_lanes)
    seal = commands.add_parser("seal")
    seal.add_argument("--request", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    seal.add_argument("--fixture", action="store_true")
    seal.set_defaults(handler=command_seal)
    verify = commands.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--fixture", action="store_true")
    verify.add_argument("--require-sealed", action="store_true")
    verify.set_defaults(handler=command_verify)
    gate = commands.add_parser("publication-gate")
    gate.add_argument("--manifest", type=Path, default=None)
    gate.add_argument("--fixture", action="store_true")
    gate.set_defaults(handler=command_publication_gate)
    status = commands.add_parser("status")
    status.add_argument("--evidence-dir", type=Path, default=None)
    status.set_defaults(handler=command_status)
    check = commands.add_parser("self-check")
    check.set_defaults(handler=command_self_check)
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        arguments.handler(arguments)
    except (PublicationError, OSError) as error:
        raise SystemExit(f"error: sealed evidence manifest: {error}") from error


if __name__ == "__main__":
    main()
