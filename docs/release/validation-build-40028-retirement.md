# Validation build 40028 retirement

Validation build 40028 is permanently retired before candidate construction
and must not be built, signed, notarized, installed, promoted, relabelled, or
used as input to a validated candidate. It is permanently classified as
`retired_before_candidate_build_source_gate_contract_incomplete`. Its reserved
but unbuilt final companion, build 40029, is permanently classified as
`retired_unbuilt_reserved_final_companion` and must not be reassigned.

## Retained pre-candidate evidence

The detached release worktree remains bound to repository commit
`faa7df2357d3f6ef1ae24c72ea384f91d9e444d4` and release-source SHA-256
`483733cf0c983e47b4ca5631cbac419a5c566e7027f0fae154d08d79fc754d04`.
Its reviewed Packet LAN peer outputs and managed release inputs were
materialized before the source gates ran. The following worktree and two P0
records are immutable historical evidence and must remain exactly in place:

- `target/release-worktrees/40028`;
- `target/release-worktrees/40028/target/candidates/0.4.0/release/evidence-inputs/p0-source-gates.json`,
  SHA-256
  `2c9727bbb3cc8dc95c8f77c79fca08659a5844c2406d8dcba425316b4f901aa2`;
- `target/release-worktrees/40028/target/candidates/0.4.0/release/evidence-attempts/source-gates/attempt-0002.json`,
  SHA-256
  `ee45a814e383106b9a54ff38cd23233f3c9d1beea0b15d2466bf5f37e70e2548`.

Do not delete, rename, copy, regenerate, replace, or promote the worktree or
either P0 record. They are failure-history evidence, not candidate evidence.

## Source-gate contract defect

The fixed P0 evidence-input path correctly retained the first failed source-gate
result. After the worktree inputs were corrected, a second run produced a
passing P0 document under the attempt-history path. Both documents bind the
same commit and release-source identity, but the v2 source-gate contract did
not define an append-only attempt journal and a unique authoritative-success
projection. Continuing would therefore require either overwriting the original
failure or ambiguously selecting between two same-source documents.

The release failed closed. Repairing this layering contract changes the release
source closure, so neither build 40028 nor build 40029 may be used for the
corrected source generation.

## No candidate or external mutation

No validation candidate or final candidate was built. In particular, there is
no build-40028 validation root, build-40029 release-build root, notary attempt,
signed candidate, Apple submission, stapled artifact, or Gatekeeper candidate
record for this pair. Neither build was installed or launched. No Host or XPC
maintenance path ran; no application, service registration, proxy, DNS, route,
or tunnel state was mutated. No physical-collector nonce or receipt was issued,
and no collector maintenance or cloud mutation occurred.

## Successor generation

The next immutable pair is validation build 40030 and final build 40031 from
one new clean source identity. Build 40030 must repeat the complete source,
test, signing, notarization, artifact, Gatekeeper, read-only runtime preflight,
installation, and physical-evidence sequence. No evidence from build 40028 may
be copied forward as successful evidence.

That successor plan was later superseded: policy retired build 40030 unbuilt,
and builds 40031, 40032, 40033, and 40034 were each retired after candidate
freeze but before canonical signing output. Build 40035 was later consumed and
retired under the same lifecycle classification. Build 40036 is the only active
GA allocation; see `ga-build-40031-retirement.md`,
`ga-build-40032-retirement.md`, `ga-build-40033-retirement.md`, and
`ga-build-40034-retirement.md`, plus `ga-build-40035-retirement.md`.
