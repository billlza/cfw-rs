# macOS 15 Network Extension Migration — Release Requirements

## Status and evidence boundary

This document is the reviewed release contract for Clash for Mac v0.4.0 on
Apple silicon and macOS 15 or newer. The source contains the Global Authority,
Host bridge, Proxy Agent, Packet Tunnel System Extension, source-built libbox
runtime, serialized Rust coordinator, and fail-closed release tooling.

Source presence, a successful unsigned build, and individually signed native
products are distinct evidence levels. Publication is forbidden until one
clean-source candidate also has a fully signed Host application, accepted
notarization, stapled tickets, Gatekeeper acceptance, physical-machine runtime
evidence, supply-chain closure, and final artifact bindings. A lower-level
success must never be reported as satisfying a higher level.

## Product identities

The release uses Team ID `YKUPL7Z869` and these fixed signing identifiers:

- Host application: `com.bill.clashformac`
- Packet Tunnel System Extension: `com.bill.clashformac.packet-tunnel`
- Proxy Agent: `com.bill.clashformac.proxy-agent`
- Global Authority: `com.bill.clashformac.global-authority`
- Shared App Group: `group.com.bill.clashformac`

The System Extension wrapper name is the Packet Tunnel signing identifier plus
`.systemextension`; the signed inner bundle identifier remains the Packet
Tunnel signing identifier. Any identifier, Team ID, wrapper, executable, or
profile mismatch is a release failure.

## 1. Platform and architecture

1. The shipped application shall target arm64 and macOS 15.0 or newer.
2. The UI shall call the existing product command boundary. It shall not access
   XPC listeners, Network Extension preferences, credentials, libbox, launchd,
   or release infrastructure directly.
3. Exactly one source-built libbox service may be active across System Proxy
   and Tunnel modes. There is no downloaded-core, legacy-helper, private API,
   executable-launch, or alternate-engine fallback.
4. Failure to establish the mandatory native authority boundary shall return a
   typed failure before network, preference, credential, or engine mutation.

## 2. Provisioning and entitlements

1. The Host, Packet Tunnel, and Proxy Agent shall use profiles issued for their
   exact bundle identifiers and Team ID.
2. The Host and Packet Tunnel profiles shall authorize their required Apple
   capabilities. The final signed code shall receive only the reviewed minimal
   entitlements; a profile authorization superset must not be copied wholesale
   into signed code.
3. The Host shall carry the App Group, Network Extension, System Extension,
   keychain, sandbox, and network grants required by the reviewed Host
   entitlement contract and no development-only or custom role grant.
4. The Packet Tunnel shall carry exactly the system-extension packet-tunnel
   role, sandbox, App Group, and required network client/server grants.
5. The Proxy Agent shall carry exactly the App Group and reviewed keychain
   access groups.
6. `get-task-allow`, debug profiles, expired or future-dated profiles, unknown
   Network Extension roles, unexpected custom entitlements, and mismatched
   signing certificates shall fail the release.

## 3. Global Authority and peer authentication

1. The application shall install one root-context Global Authority through
   `SMAppService.daemon` using the reviewed launchd property list.
2. Host, Proxy Agent, and Provider shall connect through separate fixed Mach
   services. The listener determines the role; callers cannot assert a role in
   request data.
3. Every connection shall be constrained using public Foundation code-signing
   requirements that require the exact Developer ID certificate OIDs, Team ID,
   role signing identifier, and relevant Apple entitlement values.
4. Authorization shall additionally bind the kernel-provided effective UID,
   audit session, live console user, active lease owner, connection nonce, and
   operation generation as applicable to the role.
5. A wrong Team, wrong bundle, Apple Development identity, same-Team unknown
   bundle, wrong entitlement, wrong user/session, stale connection, or replayed
   generation shall be rejected before state disclosure or mutation.

## 4. State, recovery, and failure semantics

1. Global state shall distinguish Off, Preparing, Starting, Active, Stopping,
   Recovering, Failed, and Quarantined. Failed or ambiguous state is never Off.
2. A mode switch shall stop the current owner, prove the global Off barrier,
   allocate a fresh generation, and only then prepare the next owner.
3. The durable Authority journal shall use bounded canonical records, ordered
   durability, hash chaining, descriptor-relative no-symlink access, and a
   root-owned non-App-Group directory.
4. Journal corruption, truncation, rollback, reordering, unknown fields,
   symlink substitution, owner ambiguity, or failed reattestation shall reject
   new starts and enter Recovering or Quarantined until Off is proven.
5. Cancellation after an accepted operation detaches only the caller's wait.
   Accepted work shall finish at exact readiness or compensated Off, and a
   stale callback shall not mutate a newer generation.

## 5. Tunnel operation

1. The Host shall save only a bounded, non-secret managed configuration and
   start the Packet Tunnel with one opaque, short-lived, single-use ticket.
2. The Provider shall authenticate to the Authority and redeem configuration
   and secret material exactly once before starting libbox.
3. Direct configuration or credential transport in `startVPNTunnel(options:)`
   is forbidden in production.
4. A post-save failure, cancellation, ticket expiry, start rejection, readiness
   timeout, or revocation shall stop a possibly connecting tunnel and perform
   ownership-sensitive compare-and-restore. Ambiguous cleanup is Quarantined.
5. Tunnel activation requires agreement among lease, operation context,
   configuration digest, Provider readiness, and effective operating-system
   state. `NEVPNStatus` or `utun` presence alone is not activation proof.

## 6. System Proxy operation

1. The Proxy Agent shall obtain an Authority-owned capability before libbox or
   SystemConfiguration mutation.
2. It shall apply and restore only product-owned proxy values, keep an exact
   ownership journal, and attest readiness and stop using the same operation
   context and generation.
3. Concurrent external preference edits shall not be overwritten during
   compensation. A mismatch shall fail closed instead of restoring guessed
   values.

## 7. Secrets and diagnostics

1. Tunnel tickets shall contain 32 random bytes, expire within ten seconds, be
   single-use, and be represented durably only by a digest.
2. Secret material shall remain in bounded mutable memory, be delivered once,
   and be zeroized on every success, rejection, cancellation, timeout,
   interruption, recovery, and error path.
3. Secrets shall not enter logs, errors, crash annotations, preferences,
   journals, snapshots, evidence documents, or repository artifacts.
4. Errors shall remain typed and distinguish unavailability, authorization,
   invalid input, replay, resource exhaustion, cleanup ambiguity, and internal
   failure. No catch-all success or empty-value fallback is permitted.

## 8. Build and publication evidence

1. The build shall use the pinned Rust, Swift/Xcode, Node, Go, gomobile,
   XcodeGen, Tauri, sing-box, patch, and dependency inputs recorded by the
   repository contracts.
2. Every release artifact shall bind exact source bytes, build number,
   toolchain, nested product hashes, signing mode, and artifact manifest.
3. The final Host shall be signed outside-in only after every nested product is
   placed, and then verified inside-out before and after notarization.
4. Publication requires accepted notarization with the exact submitted archive
   digest, successful staple and validation, Gatekeeper acceptance with the
   expected origin, DMG verification, final hashes, GPL corresponding source,
   notices, reviewed licenses, vulnerability results, and SPDX/CycloneDX SBOMs.
5. Signed-installed evidence requires one physical Apple-silicon machine to run
   separate clean installations of macOS 15 and the current supported macOS.
   Both runs shall bind the same machine identity and independently cover
   approval/denial, upgrade, replacement, reboot, sleep/wake, crashes,
   cancellation, multi-user/Fast User Switching, cleanup, and uninstall cases.
6. Packet evidence must use independent observations and unique tokens for
   IPv4, IPv6, TCP, UDP, QUIC, DNS A/AAAA, LAN bypass, route inclusion and
   exclusion, stop cleanup, and IPv6-disabled behavior.
7. Missing tools, permissions, profiles, evidence, logs, source cleanliness, or
   external service results shall block the associated level. No override,
   masking, warning suppression, or default-success path is allowed.
8. DMG notarization shall persist the exact pre-staple file identity and Apple
   submission ID before waiting, resume only that ID after interruption, and
   never resubmit an unknown outcome. DMG evidence and updater artifacts shall
   become uploadable only as complete canonical sealed version sets whose file
   identities and official URLs recompute exactly.
9. Each package set shall bind the exact notarized candidate app-tree and app
   manifest and shall reconstruct that identity from the completed updater
   archive or read-only-mounted final DMG. Upload authorization shall require a
   final atomic distribution seal joining both package sets to that candidate
   and to the complete CCS, SBOM, legal-review, and publication-evidence
   closure; every bound byte shall be reopened and recomputed before upload.
10. The upload allowlist shall include one atomically published, deterministic
    public-evidence bundle containing the exact CCS archive/manifest, both
    SBOMs, public manifests, GPL license, modification history, and reviewed
    third-party license/notice tree, plus a canonical path-free Gatekeeper
    projection bound to the exact private raw evidence and assessed target
    bytes. Private human legal-review, raw Gatekeeper, final-candidate, sealed
    outer, and raw physical evidence shall authorize and bind the release where
    applicable but shall not be published inside the bundle or upload allowlist.
11. Every printed GitHub release asset shall be strictly smaller than 2 GiB.
    The nested CCS archive and non-CCS public evidence shall have independent
    aggregate budgets that leave an explicit bounded reserve for the bundle
    manifest and deterministic tar/gzip container overhead.

## 9. User-visible behavior

1. Existing layout and visual structure are outside this migration and shall
   remain stable.
2. Unavailable native operations shall be shown as explicit unavailable or
   failed states, not as fabricated values or apparently successful controls.
3. Controls may become enabled only when their native capability and current
   state are proven and wired end to end.
