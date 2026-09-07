#!/usr/bin/env python3
"""Closed CLI composition root for the GA release artifact-set core."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from functools import partial
from pathlib import Path
import sys


REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))


def _run_verification_command(arguments: argparse.Namespace) -> tuple[str, ...]:
    from scripts import release_artifact_set
    from scripts.candidate_freeze import (
        CandidateFreezeError,
        frozen_candidate_verification_session,
    )
    from scripts.publication.common import PublicationError
    from scripts.publication.durable_file import DurabilityOutcomeUnknown
    from scripts.publication.ga_release_contract import (
        verify_prepackage_authorization,
        verify_publication_authorization,
    )

    primary: BaseException | None = None
    session_error: BaseException | None = None
    operation_completed = False
    publication_path: Path | None = None
    if arguments.command == "seal-updater":
        publication_path = release_artifact_set._updater_set_root(arguments.repository)
    elif arguments.command == "seal-release":
        publication_path = release_artifact_set._distribution_set_root(arguments.repository)
    publication_existed = False
    if publication_path is not None:
        try:
            publication_path.lstat()
        except FileNotFoundError:
            pass
        else:
            publication_existed = True
    try:
        with frozen_candidate_verification_session(arguments.repository) as freeze_verifier:
            archive_session = (
                release_artifact_set._updater_verification_session(arguments.repository)
                if arguments.command in {"seal-updater", "verify-updater"}
                else nullcontext(None)
            )
            with archive_session as updater_producer:
                try:
                    messages = release_artifact_set._execute_command(
                        arguments,
                        prepackage_stage_verifier=partial(
                            verify_prepackage_authorization,
                            freeze_verifier=freeze_verifier,
                        ),
                        publication_stage_verifier=partial(
                            verify_publication_authorization,
                            freeze_verifier=freeze_verifier,
                        ),
                        updater_verification_producer=updater_producer,
                    )
                except BaseException as error:
                    primary = error
                else:
                    operation_completed = True
    except BaseException as error:
        session_error = error
    if primary is not None:
        if session_error is not None:
            cleanup_note = (
                "secondary artifact verifier session cleanup failure: "
                f"{type(session_error).__name__}: {session_error}"
            )
            cleanup_note += "".join(
                f"\n{note}" for note in getattr(session_error, "__notes__", ())
            )
            primary.add_note(cleanup_note)
            if publication_path is not None and not publication_existed:
                try:
                    publication_path.lstat()
                except FileNotFoundError:
                    pass
                except OSError as observation_error:
                    unknown = DurabilityOutcomeUnknown(
                        "release publication and verifier session closure outcomes are unknown"
                    )
                    unknown.add_note(cleanup_note)
                    unknown.add_note(f"publication observation failed: {observation_error}")
                    raise unknown from primary
                else:
                    unknown = DurabilityOutcomeUnknown(
                        "new release set exists but verification and session closure failed"
                    )
                    unknown.add_note(cleanup_note)
                    raise unknown from primary
        raise primary
    if session_error is not None:
        if operation_completed and arguments.command in {"seal-updater", "seal-release"}:
            raise DurabilityOutcomeUnknown(
                "release set exists but its verification session closure outcome is unknown"
            ) from session_error
        if isinstance(session_error, CandidateFreezeError):
            raise PublicationError(
                f"candidate verification session failed: {session_error}"
            ) from session_error
        raise session_error
    return messages


def main() -> None:
    requested_command = sys.argv[1] if len(sys.argv) > 1 else ""
    if requested_command in {
        "seal-updater",
        "verify-updater",
        "verify-dmg",
        "seal-release",
        "verify-release",
    }:
        from scripts.release_python_runtime import (
            ReleasePythonRuntimeError,
            require_closed_release_runtime,
        )

        try:
            require_closed_release_runtime()
        except ReleasePythonRuntimeError as error:
            raise SystemExit(f"error: release artifact set: {error}") from error

    from scripts import release_artifact_set
    from scripts.publication.ga_release_contract import (
        verify_prepackage_authorization,
        verify_publication_authorization,
    )

    if requested_command == "self-check":
        release_artifact_set.main(
            prepackage_stage_verifier=verify_prepackage_authorization,
            publication_stage_verifier=verify_publication_authorization,
        )
    else:
        release_artifact_set.main(
            prepackage_stage_verifier=verify_prepackage_authorization,
            publication_stage_verifier=verify_publication_authorization,
            command_runner=_run_verification_command,
        )


if __name__ == "__main__":
    main()
