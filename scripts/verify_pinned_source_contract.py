#!/usr/bin/env python3
"""Verify the repository's static pinned build-input contract.

This entrypoint is intentionally source-only. It validates the complete pinned
source, tool, policy, script, protocol, and generated-artifact *identity*
contract, but it does not require the generated packet LAN peer binary to
already exist in ``target``. The independent ``packet-lan-peer`` CI lane builds
and fully verifies that artifact. Call ``verify_pinned_build_inputs.py`` when a
source-plus-artifact verification is required.
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
        "protocol, deployment, generated-artifact identity bindings, and exact "
        "artifact-source release-freeze digests"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
