#!/usr/bin/env python3
"""Closed CLI composition root for fixed GA runtime acceptance."""

from __future__ import annotations

from pathlib import Path
import sys


REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))


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

    from scripts.ga_runtime_acceptance import main as runtime_main
    from scripts.publication.ga_release_contract import (
        derive_runtime_expectation,
        verify_prepackage_authorization,
    )

    runtime_main(
        derive_runtime_expectation,
        verify_prepackage_authorization,
    )


if __name__ == "__main__":
    main()
