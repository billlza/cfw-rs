# macOS 15 Network Extension Migration — Release Design

## Design goal

The migration uses Apple's public Network Extension, System Extension,
ServiceManagement, Foundation XPC, Security, and SystemConfiguration surfaces.
It keeps UI composition stable while replacing implicit or process-local
authority with one authenticated, fail-closed machine-wide control plane.

## Module boundaries

The dependency direction is intentionally one way:

1. `CFWSharedProtocol` defines bounded wire models, identity requirements,
   errors, role-specific service names, and cross-process contracts.
2. `CFWGlobalAuthority` authenticates peers, owns the global lease/replay
   state, journals transitions, and coordinates recovery. It does not own the
   packet data plane or System Proxy implementation.
3. `CFWProxyAgent` owns the System Proxy libbox service and exact
   SystemConfiguration mutation under an Authority capability.
4. `CFWPacketTunnel` owns the Tunnel libbox service and packet flow after a
   one-use Authority ticket is redeemed.
5. `CFWAppleNetwork` is the Host-side adapter for ServiceManagement, Network
   Extension preferences, and native transition preparation.
6. `CFWNativeBridge` exposes the reviewed C ABI to Rust and maps typed native
   failures without leaking framework details into the UI.
7. The Rust application/coordinator serializes product commands and generations.
8. Tauri commands and UI code consume the application layer only.

This structure keeps operating-system I/O at native adapters, policy and state
in their owning modules, and presentation outside the trust boundary.

## Product and packaging graph

The Host application embeds:

- `Contents/Frameworks/CFWNativeBridge.framework`
- `Contents/Library/LoginItems/CFWProxyAgent.app`
- `Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension`
- `Contents/Library/HelperTools/CFWGlobalAuthority`
- `Contents/Library/LaunchDaemons/com.bill.clashformac.global-authority.plist`

The Packet Tunnel wrapper follows the system-extension packaging rule while its
signed bundle identifier remains `com.bill.clashformac.packet-tunnel`. Build
verification rejects omitted, duplicated, misplaced, or identifier-drifted
products before signing.

## Trust boundary

The Global Authority exports three role-scoped Mach services:

- `YKUPL7Z869.group.com.bill.clashformac.global-authority.host`
- `YKUPL7Z869.group.com.bill.clashformac.global-authority.proxy-agent`
- `YKUPL7Z869.group.com.bill.clashformac.global-authority.provider`

Each listener applies a public Foundation code-signing requirement before an
XPC peer is accepted. The requirement combines:

- Apple generic anchor;
- Developer ID intermediate and application certificate OIDs;
- exact Team ID `YKUPL7Z869`;
- exact role bundle identifier;
- the standard Apple capability entitlement relevant to that role.

The role is selected by the listener, never by a field supplied by the caller.
After code identity passes, authorization binds effective UID, audit session,
live console user, lease owner, connection nonce, operation ID, and generation.
The service exports its protocol only after these checks succeed.

## Provisioning and signing design

Provisioning is target-local:

| Product | Profile | Signed capability contract |
| --- | --- | --- |
| Host | exact Host Developer ID profile | reviewed Host entitlements generated deterministically |
| Packet Tunnel | exact Packet Tunnel Developer ID profile | system-extension packet-tunnel role, sandbox, App Group, network client/server |
| Proxy Agent | exact Proxy Agent Developer ID profile | App Group and reviewed keychain groups |
| Native Bridge | none | no entitlement blob |
| Global Authority | none | no functional entitlement grant |

Profiles authorize capability ceilings; they are not entitlement templates.
The Host signing entitlement file is derived from the reviewed Host plist plus
validated identity prefixes. The generator rejects debug, expired,
future-dated, wrong-platform, wrong-team, wrong-app-ID, unknown-role, and custom
grants. Xcode base-entitlement injection is disabled so `get-task-allow` cannot
appear in a Developer ID build.

The staged Global Authority executable is re-signed with an exact Developer ID
designated requirement because a generic tool requirement may otherwise permit
an Apple Development identity. The extracted binary requirement is compared to
the compiled expected requirement before publication.

## Runtime state model

The Authority owns one durable machine-wide lineage:

`Off → Preparing → Starting → Active → Stopping → Off`

Failure edges enter `Failed`, `Recovering`, or `Quarantined`; they do not jump
to Off. A transition between System Proxy and Tunnel is:

`stop owner → verify owner stopped → reconcile OS state → prove Off → allocate generation → prepare next owner`

The journal records only canonical non-secret transition and replay state. It
uses descriptor-relative no-follow file access in a root-owned directory,
bounded records, ordered durability, and hash chaining. Recovery reconstructs
the high-water lineage, never tickets or secrets. Any ambiguity prevents a new
lease.

## Tunnel start flow

1. Rust accepts a serialized Tunnel command and allocates an operation context.
2. Host authenticates to the Authority and prepares a one-use ticket before
   preference mutation.
3. Host saves and reloads a bounded non-secret `NETunnelProviderManager`
   descriptor, verifying exact ownership and configuration.
4. Host calls `startVPNTunnel(options:)` with only the opaque ticket.
5. Provider authenticates on the provider-specific Authority listener, redeems
   the ticket once, injects the returned configuration and secrets into libbox,
   zeroizes transport buffers, and attests readiness.
6. Active is published only when Authority, Provider, Host observation, digest,
   operation, and generation agree.

If any post-save step fails, the Host revokes preparation, stops a possibly
connecting tunnel, and compare-and-restores only values still owned by that
operation. Conflicting external edits produce Quarantined rather than a guessed
rollback.

## System Proxy flow

1. Rust accepts a serialized System Proxy command.
2. Host prepares the Proxy Agent through the Authority.
3. Proxy Agent authenticates on its role-specific listener and binds the exact
   owner capability before libbox or SystemConfiguration mutation.
4. Proxy Agent starts one libbox service, applies product-owned proxy values,
   records an ownership journal, and attests readiness.
5. Stop restores only exact operation-owned values and attests both engine and
   operating-system cleanup before Off can be proven.

## Cancellation, concurrency, and backpressure

Mutations are serialized. Read-only work and peer events have fixed bounds.
Overload returns typed busy or resource-exhausted failures. Only idempotent
queries may retry. Revocation and stop events are preserved under saturation.

Dropping a UI/Rust waiter does not cancel accepted native work. Completion is
one-shot and keyed by operation ID and generation, so late callbacks cannot
activate, release, or stop a newer operation.

## Evidence architecture

The release pipeline separates four levels:

1. Source implemented: reviewed source, graph, static contracts, and source
   identity.
2. Unsigned CI verified: deterministic format, lint, test, analysis, UI,
   dependency, and unsigned-candidate lanes bound to exact source/toolchain.
3. Signed installed verified: one exact signed app plus clean-machine identity,
   lifecycle, adversarial, packet, performance, and recovery evidence.
4. Sealed release evidence: accepted notarization, staple, Gatekeeper, final
   artifact hashes, corresponding source, notices, licenses, SBOMs, and
   publication bindings.

The outer manifest hashes this requirements document, this design, and the
implementation checklist. Missing or changed documents invalidate the seal.

## Current release boundary

The source architecture and native Developer ID product graph have been
implemented and exercised. That evidence does not include a clean-source Host
application, notarization, staple, Gatekeeper, installation approval, real
Tunnel/System Proxy traffic, multi-user behavior, or long-running physical
tests. The release remains blocked until those higher-level gates are produced
for the same immutable candidate.
