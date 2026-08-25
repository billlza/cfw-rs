#!/usr/bin/env python3
"""Closed CLI composition root for the GA release artifact-set core."""

from __future__ import annotations

from pathlib import Path
import sys


REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))


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

    release_artifact_set.main(
        prepackage_stage_verifier=verify_prepackage_authorization,
        publication_stage_verifier=verify_publication_authorization,
    )


if __name__ == "__main__":
    main()
