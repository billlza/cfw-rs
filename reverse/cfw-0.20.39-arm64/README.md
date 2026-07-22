# Reverse Artifacts

This directory contains local reverse-engineering artifacts extracted from the
`0.20.39` Apple Silicon macOS sample used as a behavioral baseline.

The contents here are kept strictly separate from the rebuild source tree:

- `asar/`
  Extracted JavaScript entry points and package metadata
- `metadata/`
  Hashes, file manifest and notes used to validate the sample

These files are reference material for parity work, not product source.

The upstream package declares the extracted application material as MIT and
identifies its author as Fndroid. See
[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) and
[`LICENSE.MIT`](./LICENSE.MIT). No unavailable copyright year or holder has
been inferred.
