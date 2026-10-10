#!/usr/bin/env python3
"""Verify the repository's static pinned build-input contract.

This entrypoint is source-only: it validates the complete pinned source, tool,
policy, script, and artifact-identity contract without invoking a toolchain or
requiring generated output in ``target``. It is the P0 source gate that the
build-script boundary runs and the only command-line entrypoint for the
verification implemented in ``verify_pinned_build_inputs.py``.
"""

from __future__ import annotations

from pathlib import Path
import sys

if __package__:
    from .verify_pinned_build_inputs import PinnedInputError, verify_source_contract
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from verify_pinned_build_inputs import PinnedInputError, verify_source_contract


def main() -> int:
    repository = Path(__file__).resolve().parent.parent
    try:
        verify_source_contract(repository)
    except PinnedInputError as error:
        print(f"error: pinned source contract failed: {error}", file=sys.stderr)
        return 1
    print(
        "pinned source contract verified: static source, tool, policy, script, "
        "and generated-artifact identity bindings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
