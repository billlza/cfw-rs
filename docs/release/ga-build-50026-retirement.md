# GA build 50026 retirement

GA build 50026 is permanently classified as
`retired_after_candidate_freeze_before_canonical_signing_output`. It must not
be rebuilt, resumed, re-signed, notarized, installed, promoted, relabelled, or
reused as the 0.5.0 GA application identity.

## Immutable consumed lineage

The candidate-freeze transaction completed before signing and permanently
bound build 50026 to these identities:

- repository commit:
  `de027613fe809ec3624e1c539241c2252fcf6524`;
- release-source SHA-256:
  `7b229f1be389348122176a7a0860b77693e0a1cc4539971b49814dc6829b9b15`;
- `product-input.json` file SHA-256:
  `747e258cde228c06279e17b9ff0f0c7290e912bfcfad5967f5f7f768a39388d9`;
- frozen product-input semantic SHA-256:
  `db5e3bb23328d9290ce100d531a40dfc56f840d3ee32f4dd8fd6619a6408a1e7`;
- candidate-freeze intent SHA-256:
  `2ced5c9963f82f5da06a62ced098f44a7816699bae22ff971346454575fd85ec`;
- updater-key possession-proof SHA-256:
  `9872ec52766aed9068f0a8201e92ed8700c85f2c12b261fbe5eb29cd5d7df048`;
- frozen Developer ID certificate SHA-256:
  `806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D`.

The frozen root
`target/release-worktrees/50026/target/candidates/0.5.0/ga/50026` of the
release operator checkout and every file below it are immutable historical
evidence. They must not be deleted, renamed, edited, resumed, or copied into a
later candidate.

An owner-only evidence copy is retained at
`/Users/bill/cfw-release-history/ga-build-50026-evidence/candidate`. Its
`sha256-tree-v2` root is
`e8019d74910ebf6bb622de392ca1df7c7926f5b58c60c13f10219f44b58bf73a`
over 293 entries, equal to the source tree. The source and snapshot manifests
are retained separately as `ga-build-50026-evidence.source-tree-v2.json` and
`ga-build-50026-evidence.snapshot-tree-v2.json`. The complete builder log is
retained beside the copy as `signed-build.log` (SHA-256
`0670003e760ac09907a75e53846fb67ca4bdd0bf398d57a8d2a1d15a7ceeff8d`).

## Private signing-attempt evidence

Signing attempt `00000001` invoked the fixed signing helper once. The helper
signed every nested object with the frozen Developer ID identity and a secure
timestamp, verified each of them, copied the signed native products into the
attempt's `work` directory, and promoted their manifests through
`promote_signed_native_manifest.py`. The attempt intent SHA-256 is
`2e59f4cd8df176e6ce0cad009792a2925b6262481830d36c62934b7014dbbe68`.

The helper then failed its signing-attempt-work candidate verification before
signing the Host:

```text
native UI artifact verification failed: unexpected file mode:
.../signing-attempts/00000001/work/signed-native-products/libCFMNativeDashboard.dylib.manifest.json
```

The journal reached terminal `failed` with failure code
`signing_helper_failed` and exit status 1. The terminal event file SHA-256 is
`75851bd3904cd693c8c191d70de6be9964fbdce5aa700a587f7852efc1b0c681`;
its internal `event_sha256` is
`7be698f62e37c77b6fc8db3d95d1901e43abddde7520b2f1239ddb173cd89fdc`.
Because signing had started, the transaction admits no recovery for this
attempt: it requires preserving the lineage and allocating a successor.

There is no Host signature, transformation receipt, `publish-ready`
directory, canonical `signing-output`, canonical `signed` application,
notarization transaction, Apple submission, package, installation, runtime
acceptance, tag, upload, or public release for build 50026.

## Cause

The SwiftUI dashboard library first entered a GA candidate in 50026. Its
preview builds 50001-50025 were signed outside the repository, so the GA
post-signing paths had never processed it:

- the native UI verifier required every UI manifest to be `0644`, while the
  shared durable manifest writer used by the signing helper creates them
  `0600`; this stopped 50026;
- the signing-transformation proof did not list the library, which the frozen
  app carries unsigned after build-path normalization, so it would have
  rejected the signed Host;
- the publication code closure did not admit the library as a signed-app
  binary;
- the release-app verifier transcript parser still expected six Mach-O objects
  and 34 codesign lines instead of seven and 44.

A rehearsal on the consumed attempt's real signed products and on the retained
50025 Developer ID signed application reproduced each failure with the frozen
50026 source and passed with the corrected source. Every fixed code inventory
is now checked against `native/macos/Config/signing-order.json`.

## Successor generation

Build 50027 was the only active 0.5.0 GA successor when 50026 was retired. It
was itself retired before installation on 2026-10-08
([`ga-build-50027-retirement.md`](ga-build-50027-retirement.md)); build 50028
is now the active GA. Each successor must start from one
new clean source identity and repeat the complete hosted-CI, build, freeze,
signing, notarization, publication-evidence, package, installation, runtime,
and final publication sequence. The retained installed preview 50025 remains
its migration predecessor. No application tree, profile copy, possession
proof, signature, manifest, attempt file, hosted-CI receipt, review, or
evidence tree from build 50026 may be copied forward as successful evidence.
