# macOS 15 Network Extension Migration — Implementation and Release Checklist

Checked source items mean the implementation and its local contract tests
exist. They do not imply unsigned-CI, signed-installed, notarized, or published
status. Evidence tasks stay unchecked until one immutable clean-source
candidate satisfies them.

## Source and architecture

- [x] Keep the UI behind the existing Tauri/application command boundary.
- [x] Keep Rust transition serialization and exact generation isolation.
- [x] Use one source-built libbox implementation for both supported modes.
- [x] Remove production legacy-helper, downloaded-core, private API, direct
  Tunnel payload, and provider-local authority fallback paths.
- [x] Implement stable typed errors and fail-closed unavailable behavior.
- [x] Preserve one-way cleanup/tombstone behavior for retired components.

## Global Authority

- [x] Package a root-context `SMAppService.daemon` product and launchd plist.
- [x] Export separate fixed Host, Proxy Agent, and Provider Mach services.
- [x] Authenticate each listener with exact Developer ID, Team, bundle, and
  standard Apple entitlement requirements.
- [x] Bind UID, audit session, live console user, lease owner, nonce, operation,
  and generation after code identity succeeds.
- [x] Export XPC interfaces only after authentication.
- [x] Enforce one machine-wide lease across Proxy and Tunnel owners.
- [x] Implement replay CAS, bounded canonical messages, explicit backpressure,
  heartbeat/revocation, and idempotent-query-only retry.
- [x] Implement a root-owned, descriptor-relative, no-symlink, hash-chained
  Authority journal with fail-closed recovery.
- [x] Implement bounded single-use ticket and secret zeroization paths.

## Tunnel and System Proxy wiring

- [x] Prepare Tunnel through the Authority before preference mutation.
- [x] Persist only a bounded non-secret Tunnel descriptor.
- [x] Pass only a one-use ticket through `startVPNTunnel(options:)`.
- [x] Redeem the ticket from the authenticated Provider and attest readiness.
- [x] Implement ownership-sensitive Tunnel preference compensation.
- [x] Require a Proxy Agent capability before libbox/SystemConfiguration work.
- [x] Journal exact product-owned proxy values and restore only owned values.
- [x] Route mode switches through a proven global Off barrier.
- [x] Prevent stale callbacks and dropped waiters from mutating newer work.

## Native products, profiles, and signing

- [x] Package Native Bridge, Proxy Agent, Packet Tunnel System Extension,
  Global Authority executable, and launchd plist at reviewed Host paths.
- [x] Use the required `.systemextension` wrapper while retaining the exact
  Packet Tunnel signing identifier and executable.
- [x] Keep Proxy and Packet provisioning profiles target-local.
- [x] Generate Host release entitlements deterministically from a validated
  Host profile and reviewed entitlement contract.
- [x] Reject debug, expired, future-dated, mismatched, unknown-role, custom, and
  development-only entitlement/profile states.
- [x] Disable Xcode base-entitlement injection and retain script sandboxing.
- [x] Embed a fixed Info plist in the standalone Global Authority executable.
- [x] Apply and verify the exact Developer ID designated requirement for the
  staged Global Authority executable.
- [x] Build and verify all four native products with the real Developer ID
  identity and exact installed profiles.

## Deterministic source gates

- [x] Verify the generated Xcode project against pinned XcodeGen source.
- [x] Verify native product graph, wrapper paths, signing order, and target-local
  provisioning settings.
- [x] Verify production data-plane removal and mandatory Authority ordering.
- [x] Verify profile authorization ceilings and exact signed entitlement sets.
- [x] Verify artifact manifests and native-source/source identity bindings.
- [x] Add positive and negative tests for Developer ID requirements, profile
  mismatch, custom entitlement rejection, and packaging omissions.
- [x] Bind the reviewed release requirements, design, and this checklist from a
  neutral `docs/release` path in the sealed manifest.

## Candidate and publication evidence

- [ ] Create a reviewed clean source commit without unrelated or untracked
  release inputs.
- [ ] Run every deterministic CI lane against that exact source identity with
  no errors or warnings.
- [ ] Build a complete Developer ID Host application with the validated Host
  profile and generated Host entitlement file.
- [ ] Verify the final Host and every nested product inside-out before upload.
- [ ] Submit the exact archive and record an accepted notarization result and
  issue-free log bound to its SHA-256.
- [ ] Staple and validate the application and final DMG.
- [ ] Verify Gatekeeper acceptance and expected Developer ID origin.
- [ ] Verify the DMG, final hashes, artifact manifests, source closure,
  modification notice, licenses, vulnerability reports, SPDX SBOM, and
  CycloneDX SBOM.
- [ ] Bind all outputs into the final candidate and sealed outer manifest.
- [ ] Publish only the exact sealed assets and verify their remote hashes.

## Physical Apple-silicon evidence

- [ ] Prove clean install, daemon registration approval/denial, System
  Extension approval/pending/activation, replacement, upgrade, downgrade
  refusal, reboot, and uninstall cleanup on macOS 15 and current macOS.
- [ ] Prove System Proxy, Tunnel, mode switching, cancellation, crash recovery,
  sleep/wake, login/logout/lock, and two-user Fast User Switching behavior.
- [ ] Execute the real Developer ID role authorization matrix, including wrong
  Team, bundle, identity class, entitlement, UID, session, nonce, and replay.
- [ ] Capture independent unique-token packet proof for IPv4/IPv6, TCP, UDP,
  QUIC, DNS A/AAAA, LAN bypass, included/excluded routes, stop cleanup, and
  IPv6-disabled behavior.
- [ ] Complete weak-network, connect/disconnect latency, throughput, CPU/RSS,
  descriptor growth, 100-switch, and 24-hour soak gates.

## Release decision

- [ ] Declare v0.4.0 publishable only when every unchecked candidate,
  publication, and physical-evidence item is satisfied by the same immutable
  source-bound candidate. Any unavailable input remains a blocking failure.
