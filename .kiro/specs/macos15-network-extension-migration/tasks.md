# Implementation Plan: macOS 15 Network Extension Migration

## Overview

This plan continues from the current repository baseline and implements the requirements-first design in Swift, Rust, Python, and shell. Production remains release-blocked until the P0 Global Authority boundary, ticket-only Tunnel startup, removal of provider-local authority, and fail-closed gates are source implemented. Completed items below mean reviewed source exists; they do not imply unsigned CI, signed-installed, or sealed-release evidence.

Current audit findings:
- `native/macos/Sources/CFWGlobalAuthority` and `Tests/CFWGlobalAuthorityTests` are empty; `project.yml` and `Package.swift` have no Authority product/daemon target.
- `HostBridge.swift` still puts configuration and credential bytes into `startVPNTunnel(options:)`; `PacketTunnelProvider.swift` still decodes `TunnelStartPayloadCodec` and constructs `SandboxConfigurationAcceptanceStore` plus `CrossProcessEngineLeaseStore`.
- ProxyAgent and Native Bridge also use `CrossProcessEngineLeaseStore`; required Authority-specific Rust/Swift errors are absent.
- Existing source-built libbox, Host Bridge, ProxyAgent, Packet Tunnel, bounded public packet pump, Rust coordinator, one-way legacy cleanup/tombstone, and partial release automation are reusable.
- No private Network Extension access or executable fallback was found in the reviewed production source. Legacy helper references are retirement/tombstone surfaces, not a data-plane start path.
- No Authority PBT infrastructure exists. Workspace path/name inspection found `.tauri/cfw-rs.key`; its contents were not opened. Its presence must continue to block release under Requirement 8.1.

## Tasks

- [x] 1. Preserve the reviewed source baseline
  - [x] 1.1 Retain the source-built libbox runtime, ProxyAgent, Host Bridge, Packet Tunnel, and bounded public packet pump
    - Preserve the existing public `NEPacketTunnelFlow` transport and single source-built libbox implementation while replacing only the authority boundary.
    - _Requirements: 1.2, 5.1_
  - [x] 1.2 Retain the Rust coordinator and public application command boundary
    - Preserve `EngineBackend` and `NativeBridgeCommand` product commands, serialized transitions, exact generation checks, and dropped-waiter behavior.
    - _Requirements: 3.1, 3.5, 7.1_
  - [x] 1.3 Retain one-way legacy retirement and tombstone code
    - Preserve cleanup-only legacy helper/core handling; never add a start, rollback, or fallback path to retired components.
    - _Requirements: 1.2, 7.3_
  - [x] 1.4 Retain existing source-level release and updater-key blocking foundations
    - Reuse current boundary, bundle, publication, and workspace secret scanners as inputs to the stricter evidence model; do not credit higher evidence levels yet.
    - _Requirements: 4.1, 6.5, 8.1_

- [x] 2. Establish the P0 fail-closed contracts before any production integration
  - [x] 2.1 Add the mandatory Release authority gate
    - Define `CFW_GLOBAL_AUTHORITY_REQUIRED=1` for Release and reject builds or starts before preference, network, libbox, or Tunnel mutation when Authority registration, approval, identity, availability, or compatibility is not proven.
    - Add source/build scans that reject insecure overrides and every Authority-error fallback.
    - _Requirements: 1.1, 1.2, 7.5_
  - [x] 2.2 Implement canonical bounded Authority v1 models and codecs
    - Add exact Swift schemas for protocol negotiation, envelopes, `OperationContext`, `GlobalLease`, `ReplayCursor`, `StartTicket`, snapshots, attestations, and receipts with all design limits and canonical rejection behavior.
    - Add cross-language canonical fixtures for Swift and Rust without making secret-bearing types Codable, printable, or persistent.
    - _Requirements: 2.2, 7.1_
  - [x] 2.3 Extend stable Rust and Swift Authority error contracts
    - Add all design-defined Authority error variants to `BackendErrorKind`, native wire codes, bridge mappings, retry classification, and redacted diagnostics.
    - Preserve existing public Tauri command shapes and reject localized XPC/OS text as policy input.
    - _Requirements: 3.1, 3.3, 7.1_
  - [x] 2.4 Write the property test for fail-closed Authority behavior
    - **Property 1: Authority failure is fail-closed**
    - Run at least 100 successful generated cases and record reproducible seed and shrunk counterexample output on failure.
    - **Validates: Requirements 1.1, 1.2, 2.7**
  - [x] 2.5 Write the property test for the canonical bounded codec
    - **Property 2: Canonical bounded protocol round trip**
    - Generate valid and malformed/noncanonical/oversize/version-incompatible envelopes and prove rejection occurs before state mutation.
    - **Validates: Requirements 2.2, 2.7, 6.4, 7.1**
  - [x] 2.6 Write example tests for Release gating, limits, fixtures, and error mappings
    - Cover every exact bound, unsupported feature/version, missing Authority state, stable cross-language mapping, and absence of mutation/fallback actions.
    - _Requirements: 1.1, 1.2, 2.2, 7.1_

- [x] 3. Implement the Global Authority product and pure security state machine
  - [x] 3.1 Implement exact audit-token authorization and role policy
    - Resolve kernel audit token identity through Security.framework and require exact Team ID, signing ID, designated requirement, entitlements, effective UID, audit session, role, and live-console UID conjunction.
    - Reject same-Team unknown bundles, stale PID evidence, debug/ad-hoc identities, no-console sessions, and all caller-asserted identity.
    - _Requirements: 2.3, 2.4, 6.4_
  - [x] 3.2 Implement the global lease, replay CAS, and Off-barrier reducers
    - Enforce one machine-wide prepared/active owner, immutable installation ID, lexicographically newer epoch/generation, expected revision, consumed-generation monotonicity, and non-transfer across users/connections.
    - Model Active, Off, Recovering, Stopping, and Quarantined exactly; ambiguity must never become Off.
    - _Requirements: 2.4, 2.5, 2.6, 3.2, 3.3_
  - [x] 3.3 Implement the root-owned canonical Authority journal and recovery reducer
    - Use descriptor-relative no-symlink access under a root-owned mode-`0700` non-App-Group store, bounded canonical records, ordered durability, hash chaining, and one-process serialization.
    - Reconstruct only committed high-water state; never reconstruct tickets/secrets or reset permissively after corruption, rollback, truncation, reordering, or unknown fields.
    - _Requirements: 2.6, 2.7_
  - [x] 3.4 Implement memory-only ticket and secret lifecycle primitives
    - Generate random 32-byte single-use tickets with 10-second maximum lifetime, retain only the SHA-256 for redemption, enforce all credential bounds, and zeroize Authority/transport buffers on every terminal path.
    - Ensure secrets cannot enter logs, crash annotations, preferences, journals, App Group data, snapshots, or evidence.
    - _Requirements: 2.2, 2.8_
  - [x] 3.5 Add the signed Global Authority daemon product and registration controller
    - Create the `CFWGlobalAuthority` executable/daemon target, fixed Mach service launchd plist, exact entitlements and designated requirement, app embedding/signing entries, and `SMAppService.daemon(plistName:)` registration/status controller.
    - Keep the daemon a narrow control plane with no packet, libbox, SystemConfiguration, route/DNS, arbitrary-file, shell, script, plug-in, or executable-launch API.
    - _Requirements: 1.1, 2.1, 5.1, 7.1_
  - [x] 3.6 Implement the authenticated bounded XPC service
    - Implement `CFWGlobalAuthorityXPCProtocol`, `AuthorityClient`, and `EngineOwnerAuthorityClient` with handshake/version negotiation, exact command dispatch, request correlation, one mutating transaction, bounded reads/events, explicit backpressure, and idempotent-query-only retry.
    - Authenticate before exporting interfaces and preserve revocation/stop events under saturation; reject malformed, unknown, noncanonical, incompatible, or oversized input before mutation.
    - _Requirements: 2.2, 2.3, 2.7, 7.1_
  - [x] 3.7 Wire recovery, owner liveness, console-user observation, and quarantine
    - Add bounded heartbeat/revocation channels, five-second owner stop/reattest timeouts, public live-console-user observation, restart reconciliation, and exact owner/OS Off proof handling.
    - Reject starts while Recovering; force stop on logout, Fast User Switching, identity drift, connection loss, or Authority loss, and retain Quarantined whenever cleanup is ambiguous.
    - _Requirements: 2.4, 2.5, 2.7, 3.3_

- [x] 4. Replace temporary ownership with ticket-only Tunnel and Authority-owned leases
  - [x] 4.1 Make Packet Tunnel startup redeem an Authority ticket
    - Change the Provider to accept only a bounded opaque `StartTicket`, authenticate to Authority, redeem configuration and secrets exactly once, inject them immediately into libbox, wipe transport buffers, and attest exact readiness/stopped state.
    - Remove production construction and use of `TunnelStartPayloadCodec`, `SandboxConfigurationAcceptanceStore`, and `CrossProcessEngineLeaseStore` from Provider startup; allow local lease helpers only in explicitly named test fixtures.
    - _Requirements: 1.2, 2.5, 2.8, 3.3, 7.1_
  - [x] 4.2 Make Host Tunnel startup descriptor-only and ticket-only
    - Prepare with Authority before preference mutation, store only the bounded non-secret `ConfigurationDescriptor` and network options, verify the reloaded exact manager, and call `startVPNTunnel(options:)` with only the one-use ticket.
    - Compile the direct configuration/credential options payload out of Release rather than retaining a runtime fallback.
    - _Requirements: 1.1, 1.2, 2.8, 3.1, 3.4_
  - [x] 4.3 Move ProxyAgent and native lease inspection to Global Authority
    - Require ProxyAgent to bind an Authority owner capability before libbox or System Proxy mutation, maintain heartbeat/revocation handling, and attest ready/stopped state with exact context and effective proxy observations.
    - Remove production `CrossProcessEngineLeaseStore` authority from ProxyAgent and Native Bridge and enforce machine-wide Proxy/Tunnel/multi-user exclusion only through Global Authority.
    - _Requirements: 1.2, 2.3, 2.4, 2.5, 3.1_

- [x] 5. Integrate serialized transitions, exact activation, and compensation
  - [x] 5.1 Add Host Authority clients and explicit enrollment state
    - Implement Host-side typed XPC clients plus `GlobalAuthorityServiceControlling`, registration/approval status, immutable installation enrollment, bounded request timeouts, and fail-closed connection lifecycle.
    - Expose only stable native states/errors to Rust; do not add raw Authority commands to the UI or public Tauri boundary.
    - _Requirements: 1.1, 2.1, 3.1, 7.1_
  - [x] 5.2 Require exact agreement before declaring an owner Active
    - Wire preparation, owner bind/redemption, ready attestation, Authority snapshot, configuration digest, and effective SystemConfiguration or Network Extension state into one serialized operation.
    - Classify Active only on exact lease/context/digest/owner/OS agreement and classify every mismatch as Failed, Recovering, or Quarantined.
    - _Requirements: 2.5, 3.1, 3.3_
  - [x] 5.3 Implement ownership-sensitive Tunnel preference compensation
    - Implement `ManagedTunnelPreferences` and in-memory `PreferenceMutationReceipt` staging, compare-and-restore/removal, save/reload verification, bounded stop of a possibly connecting Tunnel, Authority revocation, and terminal secret erasure.
    - Cover cancellation, reload mismatch, ticket expiry, synchronous start failure, Provider rejection, readiness timeout, and revocation; external preference conflicts must quarantine instead of being overwritten.
    - _Requirements: 3.4, 7.1, 7.3_
  - [x] 5.4 Enforce operation-scoped cancellation and callback isolation
    - Gate every accepted native/OS/owner callback by operation ID, generation, request identity, and a one-shot completion state; detach a cancelled caller while accepted work continues to exact readiness or compensated Off.
    - Extend Rust coordinator/native mappings for Authority registration, lease conflict, replay rejection, compensation conflict, cleanup uncertainty, and quarantine without changing public product command shapes.
    - _Requirements: 3.1, 3.5, 7.1_
  - [x] 5.5 Enforce the Global Off barrier for stop and cross-mode switching
    - Route stop through Authority revocation, exact owner stopped attestation, independent OS-state observation, ticket/secret/endpoint removal, and durable Off commit before allocating a fresh generation for the other mode.
    - Never treat Failed, Recovering, Quarantined, connection loss, or `NEVPNStatus` alone as Off and never restart the previous mode on failure.
    - _Requirements: 2.4, 2.5, 3.2, 3.3, 7.3_

- [x] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Implement one-way migration, recovery, and downgrade refusal
  - [x] 7.1 Add read-only inventory and Authority enrollment migration
    - Inspect temporary-path runtime, saved manager descriptor, host lineage, provider-local cursor, legacy remnants, and owner ambiguity without importing configuration or secret bytes into root persistence.
    - Stop product-owned temporary activity, prove Global Off, reconcile the managed manager, and enroll one immutable installation ID/high-water lineage only when signed Host identity and non-secret inputs agree.
    - _Requirements: 2.6, 7.3_
  - [x] 7.2 Implement fail-closed migration recovery and downgrade/uninstall handling
    - Map migration disagreement, crash ambiguity, registration denial, protocol incompatibility, downgrade, replacement, and Authority uninstall to cleanup plus proven Off or Quarantined.
    - Block older non-Authority binaries from consuming the new lineage and never start the direct-payload Tunnel, retired helper/runtime, prior mode, alternate core, or private API.
    - _Requirements: 1.2, 2.7, 7.3_
  - [x] 7.3 Add static production-boundary removal gates
    - Fail Release when production products contain direct Tunnel payload transport, provider-local acceptance/lease authority, root data-plane behavior, legacy helper startup, alternate/downloaded cores, private Network Extension access, insecure overrides, or executable fallbacks.
    - Keep cleanup/tombstone references permitted only where they cannot start or authorize a data plane.
    - _Requirements: 1.2, 5.1, 7.3, 7.5_

- [x] 8. Complete build, packaging, CI, and release-gate code
  - [x] 8.1 Package and verify the complete native product graph
    - Update SwiftPM/Xcode generation and candidate build scripts for Host, ProxyAgent, Packet Tunnel System Extension, and Global Authority daemon, including macOS 15 arm64 settings, nested signing order, launchd embedding, exact entitlements, bundle identifiers, and provisioning checks.
    - Reject missing registration assets, targets, Mach service declarations, or `CFW_GLOBAL_AUTHORITY_REQUIRED=1` in Release.
    - _Requirements: 1.1, 2.1, 5.1, 6.1_
  - [x] 8.2 Close pinned libbox and toolchain build inputs
    - Enforce Rust `1.97.1`, Node.js `24.18.0`, Go `1.26.5`, gomobile/gobind `v0.1.12`, govulncheck `v1.6.0`, sing-box commit, all three patch hashes, combined diff hash, verified module inputs, and offline release assembly.
    - Bind source tree, tool identities, XCFramework, vulnerability reports, and exact artifact hashes without accepting legacy or partial patch digests.
    - _Requirements: 5.1_
  - [x] 8.3 Implement canonical Evidence Manifest validation
    - Add the versioned manifest model, canonical parsing, content-addressed report/artifact bindings, capability highest-level classification, predecessor closure, identity/environment matching, and fail-closed promotion rules.
    - Reject duplicate/unknown required fields, stale or skipped evidence, malformed output, missing raw reports, masked failures, and source/unsigned claims promoted to installed or sealed levels.
    - _Requirements: 4.1, 6.5, 7.5_
  - [x] 8.4 Wire deterministic unsigned CI lanes
    - Add fail-closed Rust, Node, SwiftPM, unsigned Xcode build/test/analyze, boundary scan, patch/hash, cross-language fixture, vulnerability, and negative manifest-validator lanes bound to one commit and toolchain.
    - Make unavailable tools, fixtures, permissions, artifacts, timeouts, malformed outputs, nonzero exits, unconditional skips, swallowed status, warning suppression, and `|| true` fail the lane.
    - _Requirements: 4.1, 5.1, 6.5_
  - [x] 8.5 Strengthen the updater-key atomic release blocker
    - Scan repository paths/names without opening candidate key files; atomically block release, report only path/name, require external access-controlled relocation, and require rotation plus updater trust migration when exposure is plausible.
    - Preserve `.tauri/cfw-rs.key` as a release blocker until the operator resolves custody outside this coding plan; never read its contents or convert its presence into a warning.
    - _Requirements: 8.1_

- [x] 9. Add deterministic unit, integration, and property verification
  - [x] 9.1 Write the property test for exact peer authorization
    - **Property 3: Authorization is exact conjunction**
    - Run at least 100 successful generated cases across every role predicate and record reproducible seed plus shrunk counterexample output on failure.
    - **Validates: Requirements 2.3, 6.4**
  - [x] 9.2 Write the property test for global lease exclusion and non-transfer
    - **Property 4: Global lease exclusivity and non-transfer**
    - Generate concurrent owner, multi-user, crash, stop, and Fast User Switching traces and prove no simultaneous or transferred ownership.
    - **Validates: Requirements 2.4, 2.5, 3.2, 6.4**
  - [x] 9.3 Write the property test for monotonic replay CAS
    - **Property 5: Replay cursor is monotonic CAS**
    - Generate revisions, installation IDs, epochs, generations, duplicates, and reorderings with at least 100 successful cases and reproducible failure output.
    - **Validates: Requirements 2.6, 6.4**
  - [x] 9.4 Write the property test for fail-closed journal recovery
    - **Property 6: Recovery never resets permissively**
    - Generate valid, truncated, reordered, rolled-back, unknown-field, symlink, and hash-chain-invalid journal/re-attestation cases.
    - **Validates: Requirements 2.6, 2.7, 7.3**
  - [x] 9.5 Write the property test for bounded terminal secret erasure
    - **Property 7: Secret lifecycle is bounded and terminally erased**
    - Instrument every success, rejection, cancellation, expiry, interruption, recovery, and crash path and prove no serializable secret output.
    - **Validates: Requirements 2.8, 6.4**
  - [x] 9.6 Write the property test for cross-mode Off ordering
    - **Property 8: Off precedes every cross-mode start**
    - Generate mode-command traces and prove every opposite-mode prepare follows a completed Global Off barrier.
    - **Validates: Requirements 3.2, 7.3**
  - [x] 9.7 Write the property test for ownership-sensitive compensation
    - **Property 9: Preference compensation preserves external changes**
    - Generate prior values, post-save failure points, and concurrent edits and prove compare-and-restore ends only in verified Off or Quarantined.
    - **Validates: Requirements 3.4, 7.3**
  - [x] 9.8 Write the property test for cancellation and callback isolation
    - **Property 10: Cancellation and callbacks are generation-isolated**
    - Permute caller cancellation, timeout, OS/owner callbacks, and newer generations and prove one-shot, stale-safe completion.
    - **Validates: Requirements 3.5, 6.4**
  - [x] 9.9 Write the property test for evidence-level closure
    - **Property 11: Evidence levels cannot be promoted without closure**
    - Generate complete and incomplete manifests across all levels and prove every missing, stale, masked, skipped, or unbound input rejects promotion.
    - **Validates: Requirements 4.1, 6.5, 7.5**
  - [x] 9.10 Write the property test for one-way migration
    - **Property 12: Migration failures never revive a retired path**
    - Generate temporary/legacy states and all migration failures and prove emitted actions are limited to inspection, stop, cleanup, enrollment, reconciliation, or quarantine.
    - **Validates: Requirements 1.2, 7.3**
  - [x] 9.11 Add Authority protocol, service, and recovery example tests
    - Cover exact message/secret/concurrency/event bounds, busy/resource exhaustion, unsupported versions/features, identity rejection, ticket duplicate/expiry, durable-write fault injection, startup recovery, and redacted diagnostics.
    - Use pure fakes for XPC, console-user, clock, randomness, journal, and owner boundaries; do not invoke real launchd or Network Extension in generated loops.
    - _Requirements: 2.2, 2.3, 2.6, 2.7, 2.8, 6.4_
  - [x] 9.12 Add Host, ProxyAgent, Provider, and Rust integration tests
    - Exercise ticket-only startup, Authority-only owner binding, triple-agreement activation, Off-mediated switching, every compensation exit, dropped waiters, stale callbacks, registration denial, and absence of direct/local fallback.
    - Verify Swift/Rust fixtures and stable errors while preserving existing public command contracts.
    - _Requirements: 1.1, 1.2, 3.1, 3.2, 3.3, 3.4, 3.5, 7.1_
  - [x] 9.13 Add migration, build-boundary, evidence, and updater-gate tests
    - Cover inventory/enrollment disagreement, downgrade and uninstall, Release product scans, target/entitlement/plist omissions, toolchain/patch mismatches, evidence promotion negatives, unavailable probes, and path/name-only updater-key blocking.
    - Assert no fixture can enable a legacy root data plane, direct payload, private API, provider-local production authority, or fallback.
    - _Requirements: 1.2, 4.1, 5.1, 6.5, 7.3, 7.5, 8.1_

- [x] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Implement signed physical-machine and evidence capture gates
  - [x] 11.1 Implement the automated signed-installed lifecycle matrix harness
    - Build machine-readable probes for inside-out signatures, identities, entitlements, provisioning, daemon registration approval/denial, System Extension lifecycle, install/uninstall, login/logout/lock, two-user Fast User Switching, concurrent starts, cancellation, sleep/wake, reboot, upgrade/replacement/downgrade, and all four process crash cases.
    - Bind every raw result to the exact signed app tree, Apple Silicon machine hash, macOS build, operation context, and non-secret report hash; unavailable or failed probes must fail the level.
    - _Requirements: 4.1, 6.1, 6.5_
  - [x] 11.2 Implement unique-token packet-evidence automation
    - Create capture/server-observation fixtures for TCP IPv4/IPv6, UDP, QUIC, DNS A/AAAA through both resolver roles, LAN bypass, included/excluded routes, stop cleanup, and IPv6-disabled absence.
    - Reject `NEVPNStatus`, interface presence, localhost control traffic, or component logs as sole packet proof and bind every token/result to the exact candidate.
    - _Requirements: 6.2, 6.5_
  - [x] 11.3 Implement weak-network, performance, switch, and soak gates
    - Automate all three weak-network profiles, recovery/connect/disconnect p95 limits, same-machine libbox throughput/latency comparison, idle CPU/RSS limits, 100-switch RSS/FD growth, and 24-hour zero-crash soak reporting.
    - Preserve raw p50/p95/p99 samples and machine/network/power/build parameters and fail on absent controls, incomplete duration, malformed samples, or threshold violation.
    - _Requirements: 6.3, 6.5_
  - [x] 11.4 Implement separately signed adversarial client and tamper harnesses
    - Add allowed/denied client targets and automated attacks for identity predicates, inactive users, replay, duplicate ticket redemption, cursor rollback, journal tamper/truncation/symlink, malformed/deep/oversize protocol input, floods/saturation, heartbeat loss, FUS races, late callbacks, and secret extraction surfaces.
    - Bind expected denial and cleanup outcomes to exact client/candidate signatures; a missing fixture or unexecuted attack must fail Signed Installed verification.
    - _Requirements: 2.3, 2.7, 2.8, 6.4, 6.5_
  - [x] 11.5 Aggregate physical evidence with fail-closed completeness rules
    - Validate clean macOS 15 and current-macOS run sets, exact case coverage, immutable raw-report hashes, candidate identity, timestamps/tool versions, and cross-report consistency before granting Signed_Installed_Verified.
    - Keep source, unsigned, physical, and sealed claims separate and reject manual assertions or partial matrices.
    - _Requirements: 4.1, 6.1, 6.2, 6.3, 6.4, 6.5, 7.5_

- [x] 12. Complete sealed-release evidence generation and validation
  - [x] 12.1 Generate exact source, license, vulnerability, and SBOM closure
    - Produce content-addressed GPL complete corresponding source, modification notice, reviewed licenses, third-party notices, vulnerability reports, artifact hashes, SPDX SBOM, and CycloneDX SBOM bound to the patched source, XCFramework, toolchain, commit, and signed app.
    - Reject missing source/tool inputs, unreviewed license nodes, partial patches, inconsistent package graphs, or SBOM/artifact hash mismatches.
    - _Requirements: 4.1, 5.1, 6.5_
  - [x] 12.2 Bind notarization and installed evidence to the final candidate
    - Extend release validation to require accepted notarization, staple, Gatekeeper, final inside-out identities, physical matrix hashes, packet/performance/security/soak reports, and exact final artifact hashes for one unchanged app tree.
    - Any post-verification mutation, stale report, identity mismatch, missing raw evidence, or updater-key blocker must invalidate the candidate.
    - _Requirements: 4.1, 5.1, 6.1, 6.2, 6.3, 6.4, 6.5, 8.1_
  - [x] 12.3 Seal the immutable outer Evidence Manifest and publication gate
    - Emit and verify the final canonical manifest with one highest level per capability and all predecessor/report/publication bindings before publication artifacts may be created.
    - Keep publication fail closed until P0 source implementation, unsigned CI, signed-installed evidence, sealed closure, and updater-key custody requirements all pass without fallback or masking.
    - _Requirements: 1.1, 1.2, 4.1, 5.1, 6.5, 7.5, 8.1_

- [x] 13. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks 1.1–1.4 are marked complete only because the reviewed baseline source exists; they do not claim Unsigned_CI_Verified, Signed_Installed_Verified, or Sealed_Release_Evidence.
- All other implementation and evidence-gate tasks remain incomplete against the current repository. In particular, P0 remains blocked by the empty Global Authority source/test directories and the production direct-payload/provider-local authority path.
- Tasks marked with `*` are optional test implementation tasks and may be skipped for a faster coding pass, but skipping them prevents the corresponding evidence level and release gate from passing.
- Each property task corresponds to exactly one design correctness property; every run must complete at least 100 successful generated cases and preserve a reproducible seed plus the shrunk counterexample on failure.
- The plan never authorizes a retired root data plane, private API, direct-payload Release path, provider-local production authority, alternate/downloaded core, or Authority-failure fallback.
- Physical-machine tasks implement automated harnesses and fail-closed evidence validators; completion still requires running them on the specified clean signed environments and binding their raw outputs to the exact candidate.
- Task 12.2 adds the final-candidate binder (`scripts/publication/final_candidate.py`, CLI `scripts/final_candidate_binding.py`). No signed/notarized candidate exists in this workspace, so it reports `blocked` with explicit `blocked_inputs` (notarization, staple, gatekeeper, physical_evidence, post_verification, updater_key_release_blocker) and fails closed under `validate --require-verified`.
- Task 12.3 adds the immutable outer seal (`scripts/publication/sealed_manifest.py`, CLI `scripts/sealed_evidence_manifest.py`, publication gate wired into `scripts/release_publication_gate.sh`). In this workspace it seals to `blocked` with `blocked_inputs` = unsigned_ci, signed_installed, sealed_closure, final_candidate (all `not-run`) plus `updater_key_custody` (failed on `.tauri/cfw-rs.key`); only `p0_source` passes, so every capability stays at `Source_Implemented` and publication is refused with no override.
- `.tauri/cfw-rs.key` was identified by path/name only and was not opened. Its continued workspace presence blocks release until handled under Requirement 8.1.
- Task 13 final checkpoint ran four parallel read-only slices, all green: Rust `fmt`/`clippy -D warnings`/`test` (247 tests), SwiftPM DEBUG `build`/`test` (327 tests, 18 suites), release tooling `unittest` (449 tests) plus `verify_build_boundaries.sh`, all shell gate tests, every standalone verifier and `bash -n`, and the native product graph plus regenerated `CFWNative.xcodeproj`, unsigned 4-scheme `xcodebuild` lane, and the frontend `npm test`/`npm run build` (29 tests).
- The full `scripts/build_unsigned_candidate.sh` lane remains `not-run` (blocked, not accepted): the locally present `target/native-dependencies/Libbox.xcframework` was built from an older revision of the raw-packet patch and its `rawPacketPatchSha256` does not match the pinned digest in `scripts/dependency_pins.env`. Unblocking requires re-materializing the pinned sing-box source and rerunning `scripts/build_libbox.sh` with the Go toolchain; the pins and patch were not relaxed.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["2.1", "2.2", "2.3"] },
    { "id": 1, "tasks": ["3.1", "3.2", "3.3", "3.4", "3.5"] },
    { "id": 2, "tasks": ["3.6"] },
    { "id": 3, "tasks": ["2.4", "2.5", "2.6", "3.7"] },
    { "id": 4, "tasks": ["4.1", "4.2", "4.3"] },
    { "id": 5, "tasks": ["5.1"] },
    { "id": 6, "tasks": ["5.2"] },
    { "id": 7, "tasks": ["5.3"] },
    { "id": 8, "tasks": ["5.4"] },
    { "id": 9, "tasks": ["5.5"] },
    { "id": 10, "tasks": ["7.1"] },
    { "id": 11, "tasks": ["7.2", "7.3"] },
    { "id": 12, "tasks": ["8.1", "8.2"] },
    { "id": 13, "tasks": ["8.3"] },
    { "id": 14, "tasks": ["8.4", "8.5"] },
    { "id": 15, "tasks": ["9.1", "9.2", "9.3", "9.4", "9.5"] },
    { "id": 16, "tasks": ["9.6", "9.7", "9.8", "9.9", "9.10"] },
    { "id": 17, "tasks": ["9.11", "9.12", "9.13"] },
    { "id": 18, "tasks": ["11.1", "11.2", "11.3", "11.4"] },
    { "id": 19, "tasks": ["11.5"] },
    { "id": 20, "tasks": ["12.1"] },
    { "id": 21, "tasks": ["12.2"] },
    { "id": 22, "tasks": ["12.3"] }
  ]
}
```
