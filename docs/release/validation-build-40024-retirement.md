# Validation build 40024 retirement

Validation build 40024 is permanently retired and must not be installed,
promoted, rebuilt, re-signed, or submitted again. Its fixed but unbuilt final
companion, build 40025, is permanently classified as
`retired_unbuilt_reserved_final_companion` and must not be reassigned.
Build 40024 is permanently classified as
`retired_after_notarization_before_install_runtime_preflight_failed`.

## Accepted artifact evidence

- Apple submission `da1cd32b-2614-49a1-9d56-b25a1eb94431` was accepted with
  zero reported issues.
- The repository commit is
  `58971fc0fa7fb727b076cb87947f20c429d25033` and the release-source SHA-256 is
  `edaf7595d48a597ab13b0ecdfbf00297f187c7d63159077b28804b3eeb628c51`.
- The notarization archive SHA-256 is
  `8345943bc8fe982b15e63b3a0433977355a7c0fa403939f3199811be2a67aae4`.
- The stapled app passed strict code-signing verification and Gatekeeper's
  notarized Developer ID assessment.
- Its published app tree SHA-256 is
  `6a80a0c559a8cc19d609608cb215c2b7d0a4d188236e8d3315d457340e53cea7`.

These checks establish the identity and integrity of the immutable artifact;
they do not establish runtime compatibility with already installed services.

The immutable evidence roots are:

- `target/release-worktrees/40024`;
- `target/release-worktrees/40024/target/candidates/0.4.0/notary-build-claims/40024`;
- `target/release-worktrees/40024/target/candidates/0.4.0/notary-attempts/validation/40024`;
- `target/release-worktrees/40024/target/candidates/0.4.0/validation/40024`.

Do not delete, rename, copy, relabel, or use these roots as input to a new
candidate approval.

## Runtime preflight failure

The required read-only installed-service preflight failed before any service
registration mutation. Two adapter defects were confirmed:

1. The headless Host blocked the macOS process main thread while
   `NETunnelProviderManager` completion work required that thread.
2. The installed 40019 compatibility reader used `proc_pidinfo` for the root
   Authority process, an observation denied to the invoking user, and its
   Authority client/response fixtures did not match the installed role-scoped
   Mach service and synthesized Codable wire representation.

The corrected path preserves strict identity, signature, hash, PID/start-time,
UID, path, protocol-version, and Off-state validation. It does not treat a
timeout, missing field, rejected identity, or interrupted connection as Off.

## Successor generations

Validation build 40026 was later notarized and then retired before installation
when its read-only admission preflight exposed a toolchain-binding mismatch;
build 40027 remained unbuilt. Their separate immutable record is
`docs/release/validation-build-40026-retirement.md`. The next immutable pair is
validation build 40028 and final build 40029 from one new clean source identity.
