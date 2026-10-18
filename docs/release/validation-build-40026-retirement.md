# Validation build 40026 retirement

Validation build 40026 is permanently retired and must not be installed,
promoted, rebuilt, re-signed, resubmitted, relabelled, or used as input to a
validated candidate. Its reserved but unbuilt final companion, build 40027, is
permanently classified as `retired_unbuilt_reserved_final_companion` and must
not be reassigned. Build 40026 is permanently classified as
`retired_after_notarization_before_install_runtime_preflight_toolchain_binding_mismatch`.

## Accepted artifact evidence

- Apple submission `448638ab-d0b4-4789-82b1-25dcb770f8ee` was accepted with
  zero reported issues and zero warnings.
- The repository commit is
  `9f26c200fbe9ae5710634aaf7df02e89ea000e4c` and the release-source SHA-256 is
  `59b3576f1897a3ca9c8482bae8bb1587e136352e564961b44c63796482e62494`.
- The notarization archive SHA-256 is
  `1e2387c2d2805de6218271ebbcaf6496150d600b7d68f39bf70789b748815788`.
- The post-staple app tree SHA-256 is
  `ff81c562eb7fe59179b9b9a9f380d3c6d703b29aba31a6f1b568eade65d29363`.
- The app manifest file SHA-256 is
  `96035d967acc787efeaab10c06e640a305247f4fca8c678cf47b653e0ac7bffd`.
- Strict inside-out code-signing verification, stapling validation, release-app
  verification, manifest verification, and Gatekeeper's enabled Notarized
  Developer ID assessment passed.

These results prove the identity and integrity of the notarized bytes. They do
not prove that the toolchain identity sealed into those bytes was recomputed by
the same executables during installation admission.

The following roots are immutable evidence and must remain in place:

- `target/release-worktrees/40026`;
- `target/release-worktrees/40026/target/candidates/0.4.0/notary-build-claims/40026`;
- `target/release-worktrees/40026/target/candidates/0.4.0/notary-attempts/validation/40026`;
- `target/release-worktrees/40026/target/candidates/0.4.0/validation/40026`.

Do not delete, rename, copy, regenerate, or use these roots as input to another
candidate. Build 40027 was never built and must not be allocated again.

## Installation-admission failure

The read-only service-maintenance preflight rejected the candidate during
candidate binding, before Host/XPC startup, journal creation, service mutation,
application mutation, or collector maintenance. The signed build used the
release-sealed path and resolved `/usr/bin/swift` from Xcode 26.6 as Apple Swift
6.3.3. The ambient preflight path instead resolved
`/Users/bill/.swiftly/bin/swift` as Swift 6.0.3.

The candidate recorded toolchain SHA-256
`b6d72c3fdd0d25588298a8e5c608a0caf9cb40c79984323086ee496ee36d394b`,
while the ambient recomputation produced
`432c4918f5974197433669d2f1ac15496fd3f3041c0cdb37595070509f49a15b`.
All source, managed-tool tree, build, and artifact identities otherwise matched.
The mismatch was therefore a real execution-environment binding defect, not an
artifact-corruption or runtime-compatibility failure.

The corrected design uses one closed release tool environment for tool identity
and actual Swift/Xcode lane execution, resolves Apple drivers through fixed
system paths under one validated Developer directory, and removes ambient
compiler and dynamic-loader overrides. It fails rather than falling back when
the fixed selection is missing or inconsistent.

## Successor generation

The next immutable pair is validation build 40028 and final build 40029 from
one new clean source identity. Build 40028 must repeat all source, test,
signing, notarization, artifact, Gatekeeper, and read-only runtime preflight
gates before any authorized collector or installed-service maintenance begins.
