# Build 40073 retirement

Build 40073 was allocated as the single v0.4.0 GA identity on 2026-09-20 from
source `9e2f76cdd7ffb286614a7bc6fe55e75d3fc7a5b2`. It was never published. On
2026-10-05 the product decision was to add the in-app update installer to the
0.4 line before any 0.4.0 publication, which retired 40073's bytes; on
2026-10-07 the decision became to publish 0.5.0 as the next release and to
leave the 0.4 line unpublished, because the 0.5.0 line already carries every
0.4.0 change, the installer, and four weeks of corrections verified on the
installed previews 50021–50025.

40073 is retired as `retired_superseded_by_next_product_version`. This is not
a defect claim against 40073 and not an evidence retry: its frozen root,
signing, notarization and installation records remain unchanged under their
original paths and retirement documents. The v0.4.0 allocation ledger is
closed: it has no `active_ga`, every allocation is retired, and the verifier
only reads it.

The next releasable identity is 0.5.0 build 50026, allocated in
`build-allocations-v050.json` after the twenty-five consumed preview
validation lineages 50001–50025. See
[`ga-identity-plan-v050.md`](ga-identity-plan-v050.md).
