#!/usr/bin/env python3
"""Reject the retired dual-candidate v0.4.0 validation workflow.

The active release has one freeze-bound GA identity. A separately approved
validation candidate can no longer authorize a rebuild, package, or
publication decision.
"""

from __future__ import annotations

from typing import NoReturn, Sequence


RETIRED_MESSAGE = (
    "validated-candidate evidence is retired; use the single frozen GA 40043 "
    "prepackage, ga-acceptance, and publication stages"
)


def main(_argv: Sequence[str] | None = None) -> NoReturn:
    raise SystemExit(f"error: {RETIRED_MESSAGE}")


if __name__ == "__main__":
    main()
