#!/usr/bin/env python3
"""Closed CLI composition root for fixed GA runtime acceptance."""

from __future__ import annotations

from functools import partial
from pathlib import Path
import sys


REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))


def _existing_runtime_outputs(paths: tuple[Path, Path]) -> frozenset[Path]:
    present: set[Path] = set()
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        present.add(path)
    return frozenset(present)


def _run_runtime_command() -> str:
    from scripts.candidate_freeze import frozen_candidate_verification_session
    from scripts.ga_runtime_acceptance import (
        GARuntimeAcceptanceError,
        _arguments,
        _fixed_paths,
        _repository,
        main as runtime_main,
    )
    from scripts.publication.durable_file import DurabilityOutcomeUnknown
    from scripts.publication.ga_release_contract import (
        derive_runtime_expectation,
        verify_prepackage_authorization,
    )

    command = _arguments().command
    if command == "self-check":
        return runtime_main(derive_runtime_expectation, verify_prepackage_authorization)

    repository = _repository()
    output_paths = _fixed_paths(repository)
    before = _existing_runtime_outputs(output_paths) if command == "collect" else frozenset()
    message: str | None = None
    primary: BaseException | None = None
    try:
        with frozen_candidate_verification_session(repository) as freeze_verifier:
            try:
                message = runtime_main(
                    partial(derive_runtime_expectation, freeze_verifier=freeze_verifier),
                    partial(verify_prepackage_authorization, freeze_verifier=freeze_verifier),
                )
            except BaseException as error:
                # Only mandatory session cleanup runs after a body failure.
                # Defer the rethrow so cleanup cannot replace its original cause.
                primary = error
    except BaseException as cleanup:
        failure = cleanup if primary is None else primary
        if primary is not None:
            primary.add_note(
                "secondary frozen candidate verifier cleanup failure: "
                f"{type(cleanup).__name__}: {cleanup}"
            )
            for note in getattr(cleanup, "__notes__", ()):
                primary.add_note(note)
        publication_changed = False
        if command == "collect":
            try:
                publication_changed = bool(_existing_runtime_outputs(output_paths) - before)
            except OSError as observation_error:
                unknown = DurabilityOutcomeUnknown(
                    "GA runtime publication cannot be observed after verifier session failure; "
                    "inspect existing evidence before retrying"
                )
                if primary is not None:
                    unknown.add_note(f"primary runtime failure: {primary}")
                for note in getattr(failure, "__notes__", ()):
                    unknown.add_note(note)
                unknown.add_note(
                    "runtime publication observation failed: "
                    f"{type(observation_error).__name__}: {observation_error}"
                )
                raise unknown from failure
        completed_mutation = message is not None and command in {"collect", "recover"}
        if completed_mutation or publication_changed:
            unknown = DurabilityOutcomeUnknown(
                f"GA runtime {command} outcome is unknown after verifier session failure; "
                "inspect existing runtime evidence before retrying"
            )
            if primary is not None:
                unknown.add_note(f"primary runtime failure: {primary}")
            for note in getattr(failure, "__notes__", ()):
                unknown.add_note(note)
            raise unknown from failure
        raise failure

    if primary is not None:
        raise primary
    if message is None:
        raise GARuntimeAcceptanceError("runtime command returned no success diagnostic")
    return message


def main() -> None:
    source_only_self_check = sys.argv[1:] == ["self-check"]
    if not source_only_self_check:
        from scripts.release_python_runtime import (
            ReleasePythonRuntimeError,
            require_closed_release_runtime,
        )

        try:
            require_closed_release_runtime()
        except ReleasePythonRuntimeError as error:
            raise SystemExit(
                f"error: GA runtime Python admission: {error}"
            ) from error

    from scripts.candidate_freeze import CandidateFreezeError
    from scripts.publication.common import PublicationError

    try:
        message = _run_runtime_command()
    except SystemExit as error:
        notes = getattr(error, "__notes__", ())
        if notes:
            raise SystemExit(f"{error}\n" + "\n".join(notes)) from error
        raise
    except (CandidateFreezeError, OSError, PublicationError, ValueError) as error:
        notes = getattr(error, "__notes__", ())
        diagnostic = f"error: GA runtime acceptance: {error}"
        if notes:
            diagnostic += "\n" + "\n".join(notes)
        raise SystemExit(diagnostic) from error
    print(message)


if __name__ == "__main__":
    main()
