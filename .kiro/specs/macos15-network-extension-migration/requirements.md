# Requirements Document

## Introduction

This document defines the requirements for completing the `macos15-network-extension-migration` feature from the current repository baseline. The current source includes the source-built libbox runtime, ProxyAgent, Swift Host Bridge, Packet Tunnel System Extension, public bounded packet pump, Rust coordinator/native bridge, retired data-plane removal, and one-way legacy tombstone. The current source does not include the mandatory Global Authority target or production Global Authority integration; Tunnel startup still transports configuration and credentials through `startVPNTunnel(options:)` and relies on provider-local acceptance and lease stores. The feature remains release-blocked until the Global Authority boundary and all required signed, installed, physical-machine, and sealed-release evidence are complete.

## Glossary

- **Product**: The Clash for Mac application and all shipped native components for this feature.
- **Release_Build**: The production arm64 build targeting macOS 15.0 or newer.
- **Global_Authority**: The mandatory signed root-context launchd daemon that arbitrates engine ownership, replay state, and one-time Tunnel bootstrap.
- **Authority_Service**: The fixed Mach service `YKUPL7Z869.group.com.bill.clashformac.global-authority` exported by Global_Authority.
- **Authority_Protocol**: The typed, bounded, versioned XPC contract used to communicate with Global_Authority.
- **Host**: The signed application process with signing identifier `com.bill.clashformac`.
- **ProxyAgent**: The signed non-root user process with signing identifier `com.bill.clashformac.proxy-agent` that owns System_Proxy operation.
- **Provider**: The signed Packet Tunnel System Extension with signing identifier `com.bill.clashformac.packet-tunnel`.
- **Peer**: An authenticated Host, ProxyAgent, or Provider XPC connection.
- **Peer_Identity**: Identity derived from the kernel audit token and resolved code signature, including PID, effective UID, audit session, Team ID, signing identifier, designated requirement, and entitlements.
- **Live_Console_User**: The current interactive console user resolved from public SystemConfiguration state.
- **System_Proxy**: The mode in which ProxyAgent owns one libbox service and applies product-owned SystemConfiguration proxy settings.
- **Tunnel**: The mode in which Provider owns one libbox service and processes packets through public Network Extension APIs.
- **Off**: The proven global state in which no lease, ticket, secret buffer, owner endpoint, running libbox service, product-owned proxy state, or active managed Tunnel remains.
- **Global_Off_Barrier**: The durable proof of Off required between different active modes.
- **Global_Lease**: The machine-wide, non-transferable authorization for one exact owner, mode, user, operation, generation, configuration digest, and connection nonce.
- **Operation_Context**: The operation ID, installation ID, epoch, generation, mode, configuration digest, identity digest, owner UID, and Authority revision bound to one transition.
- **Replay_Cursor**: The durable Global_Authority high-water installation ID, epoch, generation, and revision used to reject replay.
- **CAS**: Compare-and-swap acceptance that commits only when the expected Authority revision and replay lineage match current durable state.
- **Authority_Journal**: The canonical, versioned, root-owned, non-secret transition and replay log.
- **Start_Ticket**: A random 32-byte, single-use, memory-only Tunnel bootstrap capability with a maximum lifetime of 10 seconds.
- **Secret_Material**: Credential bytes supplied for immediate Tunnel engine injection.
- **Configuration_Descriptor**: The bounded non-secret identity and network options saved with the managed Tunnel configuration.
- **Managed_Tunnel_Manager**: The exact product-owned `NETunnelProviderManager` identified by Configuration_Descriptor.
- **Preference_Mutation_Receipt**: The in-memory record of the prior manager values and exact values written by one operation.
- **Compensation**: Ownership-sensitive compare-and-restore cleanup after a post-save Tunnel start failure.
- **Quarantined**: The fail-closed state used when owner, journal, replay, preference, or operating-system cleanup cannot be proven.
- **Recovering**: The Global_Authority restart state that rejects new starts while durable state and owner status are reconciled.
- **Source_Implemented**: Evidence Level 1: reviewed source, build graph, static boundary checks, and source hashes bound to the feature.
- **Unsigned_CI_Verified**: Evidence Level 2: Source_Implemented plus exact unsigned artifacts and passing deterministic test and analysis reports bound to one commit and toolchain.
- **Signed_Installed_Verified**: Evidence Level 3: Unsigned_CI_Verified plus exact signed identities and physical-machine installed and runtime evidence bound to one signed app tree.
- **Sealed_Release_Evidence**: Evidence Level 4: Signed_Installed_Verified plus notarization, staple, Gatekeeper, final hashes, publication, license, source, and SBOM closure.
- **Evidence_Manifest**: The canonical machine-verifiable manifest that binds evidence levels, source, tools, artifacts, identities, machines, tests, and publication outputs.
- **Release_Gate**: The fail-closed validator that decides whether a candidate satisfies an evidence level or may be published.
- **Test_Suite**: The deterministic example-based, integration, and property-based verification for the feature.
- **Feature_Specification**: The requirements, design, task, decision, and risk documentation for this feature.
- **libbox**: The sole source-built sing-box library runtime permitted to own the Product data plane.
- **XPC**: The Apple interprocess communication mechanism used by authenticated native component protocols.
- **CCS**: GPL complete corresponding source for the exact shipped binary.
- **SBOM**: Software bill of materials in both SPDX and CycloneDX formats.
- **Legacy_Path**: The retired root helper, temporary direct-payload Tunnel path, previous runtime, downloaded or alternate core, or private Network Extension API path.
- **Packet_Evidence**: A unique-token packet capture or independent server observation proving real data-plane behavior.
- **Updater_Key_File**: Any ignored updater-key-named `.key` or `.pem` file located inside the repository workspace.

## Requirements

### Requirement 1: Production Boundary and Fail-Closed Authority

**User Story:** As a release operator, I want production network operation to depend on the Global Authority, so that an unavailable security boundary cannot enable an unarbitrated engine.

#### Acceptance Criteria

1. IF Global_Authority registration, approval, availability, identity authentication, or protocol compatibility is absent, denied, or unsuccessful before a start, THEN THE Release_Build SHALL define `CFW_GLOBAL_AUTHORITY_REQUIRED=1`, return a typed Authority failure before preference mutation, network mutation, libbox startup, or Tunnel startup, and remain Off, Failed, or Quarantined.
2. THE Release_Build SHALL exclude every runtime transition from a Global_Authority failure to a retired root data-plane helper, Legacy_Path, direct configuration or credential payload in `startVPNTunnel(options:)`, provider-local production authority, alternate core, downloaded core, private Network Extension API, shell, script, plug-in, or executable-launch fallback.

### Requirement 2: Mandatory Global Authority and Secure Control Plane

**User Story:** As a system owner, I want one authenticated machine-wide control authority, so that Proxy, Tunnel, replay, secret, and multi-user decisions have one enforceable source of truth.

#### Acceptance Criteria

1. THE Product SHALL install Global_Authority as a signed root-context launchd daemon through `SMAppService.daemon(plistName:)`, embed the launchd property list under `Contents/Library/LaunchDaemons`, export Authority_Service, and provide no packet, socket-forwarding, libbox, route, DNS, SystemConfiguration, arbitrary-file, shell, script, plug-in, or executable-launch interface from Global_Authority.
2. THE Authority_Protocol SHALL accept only canonical version-1 typed envelopes with exact schemas, reject unsupported major versions, required features, unknown commands, duplicate fields, noncanonical encodings, and bound violations before state mutation, enforce a 1 MiB envelope limit, a 768 KiB secret-free configuration limit, a 256 KiB total Secret_Material limit, 128 credential slots, a 16 KiB individual secret limit, 64 global in-flight read-only requests, one mutating transaction, 32 queued events per Peer, a 10-second preparation lifetime, and a five-second command or stop-attestation timeout, apply explicit busy or resource-exhausted backpressure, preserve revocation and stop events, and retry only idempotent read-only queries.
3. WHEN a Peer requests an Authority_Protocol operation, THE Global_Authority SHALL authorize the operation from the kernel audit token by requiring Team ID `YKUPL7Z869`, the exact role signing identifier, the exact designated requirement, exact entitlement values, the resolved effective UID and audit session, and the exact role rule that Host matches Live_Console_User, ProxyAgent matches both Global_Lease owner and Live_Console_User, or Provider matches the root system-extension context.
4. WHEN Global_Authority detects a Live_Console_User change, absent console user, connection invalidation, heartbeat loss, shutdown condition, owner identity drift, or security-policy revocation, THE Global_Authority SHALL revoke the existing Global_Lease, order the existing owner to stop within five seconds, enter a critical fail-closed stop state when non-transfer enforcement fails, prevent lease transfer or state disclosure to another user, and reject a new preparation until Global_Off_Barrier is proven.
5. THE Global_Authority SHALL enforce one machine-wide Global_Lease that permits no more than one prepared or active engine owner and no more than one running libbox service across System_Proxy, Tunnel, login sessions, and users.
6. WHEN a Host submits a start preparation, THE Global_Authority SHALL use one atomic CAS to require the immutable installation ID, a lexicographically newer epoch and generation, the expected Authority revision, Off state, and no pending operation before durably advancing Replay_Cursor and issuing an owner capability or Start_Ticket.
7. WHEN Global_Authority starts, restarts, loses an active owner channel, detects protocol incompatibility, or detects an invalid, truncated, reordered, rolled-back, unknown-field, symlinked, or hash-chain-inconsistent Authority_Journal, THE Product SHALL reject new starts, validate the bounded journal from a root-owned mode-`0700` descriptor-relative non-App-Group store without following symlinks, reconstruct the exact durable high-water state, avoid reconstructing Start_Tickets or Secret_Material, require exact authenticated owner reattestation within five seconds, direct an orderly fail-closed stop when reattestation is unavailable, and enter Recovering or Quarantined until explicit Off reconciliation proves cleanup.
8. WHEN Global_Authority accepts a Tunnel preparation, THE Global_Authority SHALL keep bounded Secret_Material and the Start_Ticket only in mutable process memory, retain only the Start_Ticket SHA-256 for redemption, return Secret_Material exactly once to the authenticated Provider, exclude Secret_Material from logs, crash annotations, preferences, Authority_Journal, App Group storage, snapshots, and evidence, and zeroize Authority-owned and transport-owned buffers on success, rejection, cancellation, expiry, interruption, crash recovery, and error paths.

### Requirement 3: Serialized Mode Transitions and Failure Compensation

**User Story:** As a user, I want mode transitions to be serialized and recoverable, so that failed or cancelled work cannot leave conflicting network ownership.

#### Acceptance Criteria

1. THE Product SHALL route mode control through the Rust coordinator, Host, Global_Authority, and exact ProxyAgent or Provider owner while retaining the existing public Rust product command boundary and preventing UI access to raw Authority_Protocol operations.
2. WHEN a transition changes System_Proxy to Tunnel or Tunnel to System_Proxy, THE Product SHALL stop the current owner, prove Global_Off_Barrier, allocate a fresh generation, and only then prepare the target mode.
3. THE Product SHALL classify Active only when Global_Lease, Operation_Context, owner-ready attestation, configuration digest, and effective operating-system state agree exactly, classify Off only when all Global_Off_Barrier predicates are proven, and classify every cleanup ambiguity as Recovering or Quarantined.
4. WHEN Managed_Tunnel_Manager preference save succeeds and cancellation, reload mismatch, Start_Ticket expiry, synchronous start failure, Provider rejection, readiness timeout, or Authority revocation occurs before exact Tunnel activation, THE Host SHALL revoke and zeroize the preparation, stop a possibly connecting Tunnel, compare-and-restore only operation-owned manager values, save and reload the result, and finish in verified Off or Quarantined.
5. WHEN any cancellation or callback occurs after operation acceptance, THE Product SHALL gate the event by operation ID, generation, request identity, and one-shot completion state regardless of native work status so accepted work continues to exact readiness or compensated Off and stale or late callbacks cannot activate, release, stop, or mutate a newer operation.

### Requirement 4: Evidence-Level Completion

**User Story:** As a release reviewer, I want capability claims bound to explicit evidence levels, so that source presence cannot be mistaken for installed or release proof.

#### Acceptance Criteria

1. THE Evidence_Manifest SHALL assign each capability exactly one highest achieved level from Source_Implemented, Unsigned_CI_Verified, Signed_Installed_Verified, and Sealed_Release_Evidence and reject promotion when a predecessor, exact artifact or environment binding, content hash, raw report, required command result, identity proof, physical-machine proof, or publication artifact is absent, stale, skipped, masked, malformed, or unsuccessful.

### Requirement 5: Platform, Source, Toolchain, and Publication Closure

**User Story:** As a distributor, I want every shipped native byte tied to fixed source and toolchain inputs, so that the macOS product is reproducible, auditable, and license-complete.

#### Acceptance Criteria

1. THE Release_Build SHALL target arm64 and macOS 15.0 or newer, license the Product under GPL-3.0-or-later, permit exactly one active mode and one running source-built libbox service, use Rust `1.97.1`, Node.js `24.18.0`, Go `1.26.5`, gomobile and gobind `v0.1.12`, govulncheck `v1.6.0`, and sing-box `v1.13.14` commit `25a600db24f7680ad9806ce5427bd0ab8afe1114`, apply the three design-pinned patches with SHA-256 values `ca751c4ec4b82a60d4dd8716627dc2665b154901a988603108bb5e4e718cf439`, `5e578e7f3695116f8e1dfbb3fc7c2fc276c9b8c193428e5fd6fa71dc57fb8d60`, and `d52fc83c28b5baa919a4d1590a90f7353daaa3120b6ac39aa8e4476133c602d3`, verify combined diff SHA-256 `f3d84e99e7832495975e4d78fd73744f63c1d0f79393b7276cce2f6e3e80c233`, build the release offline from the verified patched source, and bind the source tree, module hashes, Xcode and Swift identities, complete tool identities, XCFramework, signed app, CCS, modification notice, reviewed licenses, third-party notices, vulnerability reports, artifact hashes, SPDX SBOM, and CycloneDX SBOM in Evidence_Manifest.

### Requirement 6: Installed, Packet, Performance, Stability, and Security Gates

**User Story:** As a release operator, I want signed physical-machine and adversarial evidence, so that CI success alone cannot authorize publication.

#### Acceptance Criteria

1. WHEN a candidate seeks Signed_Installed_Verified, THE Release_Gate SHALL require clean physical Apple Silicon runs on macOS 15 and current macOS that verify inside-out signatures, exact Team ID, bundle identifiers, entitlements, provisioning, daemon registration approval and denial, System Extension approval, pending approval, restart, upgrade, replacement, downgrade refusal, install and uninstall cleanup, login, logout, lock, Fast User Switching with at least two users, concurrent starts, cancellation, sleep and wake, reboot recovery, and Host, Global_Authority, ProxyAgent, and Provider crashes.
2. WHEN a candidate seeks Signed_Installed_Verified, THE Release_Gate SHALL require unique-token Packet_Evidence for TCP over IPv4, TCP over IPv6, UDP, QUIC, DNS A and AAAA through both resolver failover roles, LAN bypass, included routes, excluded routes, stop cleanup, and IPv6-disabled absence, using packet capture or independent server observation rather than `NEVPNStatus`, interface presence, localhost control traffic, or component logs alone.
3. WHEN a candidate seeks Signed_Installed_Verified, THE Release_Gate SHALL require weak-network results for 100 ms latency with 1% loss at 10 Mbps, 300 ms latency with 5% loss at 1 Mbps, and a 30-second outage; recovery p95 no greater than 10 seconds; connect p95 no greater than 5 seconds; disconnect p95 no greater than 3 seconds; throughput at least 90% of the same-machine libbox baseline; added latency no greater than 10%; active idle CPU below 1%; active RSS no greater than 120 MiB; 100 switches with RSS growth no greater than 5 MiB and file-descriptor growth no greater than 2; and a 24-hour soak with zero crashes.
4. WHEN a candidate seeks Signed_Installed_Verified, THE Release_Gate SHALL require separately signed allowed-client and denied-client tests for wrong Team ID, bundle identifier, designated requirement, entitlement, UID, audit session, stale PID or audit evidence, inactive console user, same-Team unknown bundle, replayed operation, replayed Start_Ticket, duplicate redemption, Replay_Cursor rollback, Authority_Journal truncation, tampering and symlink attacks, oversize, deep and noncanonical messages, request floods, in-flight and event-queue saturation, heartbeat loss, Fast User Switching races, late callbacks, and attempted secret extraction from logs, preferences, journals, crash records, snapshots, and evidence.
5. WHEN any required verification command, probe, tool, fixture, artifact, permission, expected output, or attack case is unavailable, skipped, times out, returns malformed output, or exits unsuccessfully, THE Release_Gate SHALL fail the associated evidence level immediately regardless of other available results and reject `|| true`, unconditional skips, swallowed exit status, warning suppression, or conversion of unavailability into success.

### Requirement 7: Executable Contracts, Correctness, and One-Way Migration

**User Story:** As a maintainer, I want executable contracts and one-way recovery rules, so that implementation and tests preserve the security model throughout migration.

#### Acceptance Criteria

1. THE Product SHALL implement the design-defined `CFWGlobalAuthorityXPCProtocol`, `AuthorityClient`, `EngineOwnerAuthorityClient`, `GlobalAuthorityServiceControlling`, `ManagedTunnelPreferences`, Operation_Context, Global_Lease, Replay_Cursor, Start_Ticket, Authority snapshot, ready and stopped attestations, and Preference_Mutation_Receipt with exact bounded schemas and stable typed Rust error mappings.
2. WHEN pure Global_Authority logic is tested, THE Test_Suite SHALL run at least 100 successful generated cases for each design correctness property covering fail-closed Authority behavior, canonical codec round trips, exact authorization, global lease exclusion, replay CAS, journal recovery, secret lifecycle, Off ordering, compensation, callback isolation, evidence validation, and migration without Legacy_Path revival while recording a reproducible seed and shrunk counterexample for each failure.
3. WHEN upgrade inventory finds any issue, including temporary-path activity, ambiguous ownership, migration disagreement, crash-recovery ambiguity, downgrade, Authority uninstall, registration denial, or protocol incompatibility, THE Product SHALL perform only read-only inspection, product-owned stop, cleanup, explicit Authority enrollment, reconciliation, or quarantine actions and terminate in proven Off or Quarantined without starting Legacy_Path or a previous mode.
4. THE Feature_Specification SHALL record the root control-plane decision, documented ServiceManagement installation model, authenticated XPC trust boundary, multi-user policy, memory-only Tunnel secret boundary, Off barrier, compensation policy, recovery and quarantine policy, cancellation semantics, migration policy, evidence hierarchy, release risks, and deferred documentation synchronization identified by the design.
5. WHEN implementation status is reported, THE Evidence_Manifest SHALL distinguish source existence from Unsigned_CI_Verified, Signed_Installed_Verified, and Sealed_Release_Evidence and preserve the current P0 status until Global_Authority and production removal of the temporary direct Tunnel payload and provider-local authority are Source_Implemented.

### Requirement 8: Updater-Key Release Blocking

**User Story:** As a security owner, I want repository-local updater key material to block release, so that ignored files cannot bypass key custody controls.

#### Acceptance Criteria

1. IF an Updater_Key_File exists anywhere inside the repository workspace, THEN THE Release_Gate SHALL execute one atomic security response that blocks release, inspects and reports only the file path and name without opening or reading file contents, requires relocation to an access-controlled external store, prevents omission of any response step, and requires key rotation plus an updater trust migration when backup, archive, or sharing exposure is plausible.
