# CFW native macOS network boundary

This directory contains the macOS 15+, Apple Silicon-only boundary for the
network-stack migration. The production Xcode graph links the pinned,
source-built libbox runtime into both native owners and fails closed if any
native product, identity, configuration, or Global Authority proof is absent.
Source and unsigned-build completion are not claims that the installed,
Developer ID-signed process graph has passed its physical data-plane gates.

## Layout

- `CFWSharedProtocol` owns bounded versioned DTOs, configuration identities,
  the Authority v1 codec, role-scoped XPC contracts, event queues, and the
  public code-signing requirements shared by Host and both native owners.
- `CFWGlobalAuthority` is the root-context, non-networking lease authority. It
  owns a descriptor-relative, root-owned hash-chained recovery journal, one
  machine-wide Proxy/Tunnel lease, liveness and fast-user-switch revocation,
  exact stop/Off reconciliation, and three role-specific Mach services. It
  never launches a core or reads arbitrary paths.
- `CFWPacketTransport` bridges the public `NEPacketTunnelFlow` methods to a
  bounded nonblocking `SOCK_DGRAM` socketpair. It never accesses private object
  fields or file descriptors through KVC.
- `CFWAppleNetwork` is the host-side `SystemExtensions` and
  `NETunnelProviderManager` adapter. It registers the embedded Global Authority
  daemon with `SMAppService`, prepares single-use Authority tickets/capabilities,
  and requires exact provider generation/digest readiness.
- `CFWNativeBridge` is the fixed C ABI consumed by Rust. Its production
  coordinator constructs the authenticated Host Authority client, signed
  ProxyAgent transport, Network Extension Host bridge, and host-only credential
  vault; secret-bearing runtime configuration crosses authenticated XPC only in
  bounded memory and has no App Group file-store production path.
- `CFWPacketTunnel` contains the `NEPacketTunnelProvider`. Its production
  factory is `LibboxPacketEngineFactory`; it redeems only a single-use opaque
  ticket over the Provider-specific Authority service before accepting
  configuration or credentials.
- `CFWProxyAgent` is a non-root `SMAppService.agent`. It authenticates the Host
  before exposing its bounded XPC API, binds a single-use Authority owner
  capability before libbox or SystemConfiguration mutation, and constructs
  `LibboxProxyEngineFactory` plus the transactional proxy owner.
- `CFWLibboxRuntime` and `CFWLibboxObjC` are the only native libbox adapters.
  The Xcode products link the source-built XCFramework and do not search for a
  downloaded or user-selected core.

Tunnel network settings bind the private-network bypass bit into the signed
configuration identity. When enabled, the provider excludes IPv4 loopback,
RFC1918 and link-local ranges plus IPv6 loopback, ULA and link-local ranges;
when disabled it publishes no such exclusions. DNS points only at
provider-owned virtual peers in reserved address space and captures the default
resolver domain. Release remains blocked until libbox is proven to service
those peers without an external resolver fallback.

The Xcode `CFWProxyAgent` product is a background-only, arm64 `.app`, suitable
for embedding as a signed user agent. `CFWProxyAgentCore` is the single static
module shared by that executable and its tests. The Host registration path uses
`SMAppService.agent`; provisioning, user approval where required, Developer ID
signing, and installed identity behavior remain release-pipeline and physical-
machine responsibilities. The unsigned validation build intentionally cannot
pass the production Team ID policy.

System proxy activation is transactional. The engine must first report a
validated `127.0.0.1` mixed-listener endpoint. ProxyAgent then captures only the
HTTP, HTTPS, SOCKS, PAC-enable, and auto-discovery-enable fields for each enabled
network service, persists a prepared ownership journal, applies all changes in
one authorized SCPreferences commit/apply cycle, verifies the result, and marks
the journal applied. Each transaction uses `AuthorizationCreate`,
`SCPreferencesCreateWithAuthorization`, and `AuthorizationFree` with destroyed
rights; failures are typed and are never projected as success. The journal
contains no credentials, PAC URL, scripts, or profile
content. Its complete, bounded canonical value is one authoritative Data
Protection Keychain item; it is not mirrored into App Group storage, avoiding a
cross-store commit window. Stop and crash recovery restore a field only when it
still equals this product's applied value; fields already restored are
idempotent, and external values are retained and reported as explicit ownership
conflicts. A prepared journal is also recoverable after a crash between
preference application and the final journal phase update.
Recovery republishes SCPreferences even when the persisted fields already equal
their originals, covering a prior commit-success/apply-failure window. The
journal is removed only after the effective primary-service proxy state matches
the expected restored state. A signed physical run must still prove unattended
recovery after Authorization Services rights expire; the current non-root
boundary is not evidence that crash or fast-user-switch cleanup can always
obtain a fresh right without interaction.

The Rust coordinator remains the single writer of product intent. Swift state
objects are observations/wire DTOs, not a second product state machine. The
root Global Authority is the single durable machine-wide arbiter; no App Group
`engine.lock` participates in production ownership. Host, ProxyAgent, and
Provider connect to separate role-scoped Mach services whose listener and
client both apply exact public code-signing requirements. The service also
revalidates the public process/effective-user/audit-session properties against
the live console user and current lease owner before exporting a peer.

The Host prepares a Proxy owner capability or Tunnel start ticket before any
data-plane mutation. ProxyAgent binds its capability; Provider redeems its
single-use ticket and receives bounded configuration and ephemeral secrets only
in memory. Each owner must attest exact readiness, maintain the Authority
heartbeat/event channel, and stop on revocation or disconnection. Cooperative
stop is ordered as Authority `beginStop`, owner teardown and stopped
attestation, Host observation of the OS-facing Off boundary, then Authority
`completeStop`. Failures remain Stopping or Quarantined rather than fabricating
Off or transferring the lease.

The loopback controller capability belongs to one Host process. After a Host
crash or replacement, startup never adopts a still-active native owner: it
validates the durable lineage, orders the exact owner stop, independently
queries the native boundary for global Off, and only then reports Off. A later
user start allocates a fresh generation and capability. This avoids both
persisting the controller token and presenting an Active runtime that the new
Host cannot authenticate to.

On daemon restart, the hash-chained root journal restores only the immutable
lineage/revision cursor and enters Recovering. It never reconstructs a ticket,
capability, configuration, credential, or executable lease. The Host registers
ProxyAgent so its persisted SystemConfiguration ownership recovery can run,
observes both native owners and public Network Extension state, then uses an
exact compare-and-swap `reconcileOff` request. Ambiguous, truncated, reordered,
rolled-back, or identity-mismatched recovery is quarantined.

Every start attempt must use a newer generation. A provider crash therefore
does not authorize an OS restart with the saved descriptor: the Rust
coordinator must observe the failure, persist the next generation, and start
again. The Authority journal currently has fixed 4,096-record and 32 MiB limits
without compaction; a crash-safe bounded compaction/checkpoint design or an
enforced non-exhaustion lifetime contract remains a release requirement.

Canceling an installation wait is distinct from stopping a tunnel. Apple does
not expose a public API for withdrawing a submitted System Extension activation
request, so `cancelTunnelInstallationWait` only detaches the local continuation
and suppresses stale approval/completion callbacks. The request remains
identity-bound until its delegate terminal callback, and runtime
`stopTunnel(expectedConfiguration:)` continues to reject a missing or
generation-mismatched manager as stale. The coordinator must reconcile the
eventual OS installation state instead of reporting that approval was revoked.

The generated Xcode project builds the provider implementation as the
`CFWPacketTunnel` static module and links it into the
`CFWPacketTunnelExtension` System Extension target. Its distribution wrapper is
named `com.bill.clashformac.packet-tunnel.systemextension`, exactly matching
the target's bundle identifier as required by System Extension registration,
while `CFBundleExecutable` remains the explicit `CFWPacketTunnel` Mach-O name.
This keeps one provider implementation while allowing its pure lifecycle
controller to be unit tested outside a Network Extension process; the
Info.plist names `CFWPacketTunnel.PacketTunnelProvider` explicitly.

Tunnel descriptors carry explicit IPv6 and MTU options. IPv4 uses the RFC 2544
benchmarking subnet `198.18.64.1/30` with peer/DNS `198.18.64.2`; IPv6 uses the
RFC 5180 benchmarking subnet `2001:2:0:64::1/126` with peer/DNS
`2001:2:0:64::2`. These addresses are intentionally outside the LAN bypass
prefixes. Disabling IPv6 removes both the IPv6 default route and IPv6 resolver
from Network Extension settings.

The descriptor-only manager contract also requires VPN On Demand to be disabled
with no non-empty rules. An inherited enabled/rule-bearing manager is rejected
before any preference write because rule contents are outside the non-secret WAL.
Every create/restore explicitly clears On Demand and verifies the full bounded
manager state after reloading preferences.

## Build and test

Fast, unsigned validation:

```sh
./scripts/run_release_ci_gate.sh prepare-cargo-workspace-inputs
./scripts/run_release_ci_gate.sh bootstrap-policy-tools
./scripts/run_release_ci_gate.sh bootstrap-release-toolchain
./scripts/run_release_ci_gate.sh swift-package-test
```

The preparation gates are idempotent after their exact pinned inputs have been
sealed. They must run before any validation gate so Rust and policy-tool
execution cannot inherit an ambient Cargo source or configuration.

Validate the tracked Xcode project against the pinned XcodeGen build, then
build the four immutable native products in a candidate-specific directory:

```sh
./scripts/run_release_ci_gate.sh verify-xcode-project
./scripts/run_release_ci_gate.sh build-script-boundary

export CFW_BUILD_NUMBER=40000
export CFW_NATIVE_PRODUCTS_OUTPUT="$PWD/target/candidates/0.4.0/native-validation/40000/native-products"
./scripts/run_release_ci_gate.sh build-native-products-unsigned
./scripts/run_release_ci_gate.sh xcode-unsigned-test
```

Automatic Swift-to-Objective-C header installation is disabled for every native
target (`SWIFT_INSTALL_OBJC_HEADER=NO`). Internal modules communicate through
Swift/XPC, while the reviewed `Headers/CFWNativeBridge.h` C ABI is declared as a
public header on the `CFWNativeBridge` framework and installed by its Xcode
Public Headers build phase. User Script Sandboxing remains enabled for every
target; there is no static-library exception. `verify_xcode_project.sh`
regenerates the project with the pinned XcodeGen toolchain and compares it with
the tracked project, while `verify_native_product_graph.py` rejects a generated
Swift Objective-C header-copy phase and requires the explicit header boundary.

Signed activation additionally requires matching Developer ID provisioning for
`com.bill.clashformac`, `com.bill.clashformac.packet-tunnel`, the System
Extension/Network Extension capabilities, `com.bill.clashformac.proxy-agent`,
the Host, and the shared App Group/Keychain groups. It also requires installation
approval and the exact role-scoped XPC identities on a physical machine. Never
add a development entitlement or unsigned-identity fallback.

The Packet Tunnel App Group entitlement is required to look up its sandboxed
Provider-to-LaunchDaemon Mach service. Provider production code does not resolve
that shared container: libbox uses the System Extension's own Application Support
container, and the release boundary forbids construction of an App Group runtime
configuration store. The entitlement does not make the logged-in app and root
system extension resolve the same filesystem container. The Packet Tunnel target
intentionally has no user Keychain access-group entitlement.

Apple references:

- [Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [TN3134: Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Network Extension Provider Packaging](https://developer.apple.com/forums/thread/800887)
- [Installing system extensions and drivers](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers)

## libbox composition and remaining evidence

`Dependencies.lock.json` pins sing-box `v1.13.15` at commit
`3708fa18766cda1f11b77f6ed9c7bd61688f17df`, Go `1.26.6`, and gomobile
`v0.1.13` at commit `9f03b8f25789099c5c8abef4a02085da783ba923`. The
materialization step applies four digest-pinned patches in a
fixed order:

1. `sing-box-v1.13.15-security-dependencies.patch` updates the pinned Go module
   graph, including go-chi `v5.3.0`, `x/crypto v0.55.0`, `x/mod v0.40.0`,
   `x/net v0.58.0`, `x/sync v0.22.0`, `x/sys v0.47.0`, `x/term v0.45.0`,
   `x/text v0.41.0`, `x/tools v0.49.0`, gRPC, and their exact coupled
   requirements. The `x/mod` refresh removes the module-level
   `GO-2026-6179` and `GO-2026-6180` findings without an ignore.
2. `sing-box-v1.13.15-raw-packet-tun.patch` adds the explicit Darwin raw-packet
   contract. It accepts only a connected `AF_UNIX/SOCK_DGRAM` descriptor,
   validates MTU/routing/GSO constraints, transfers descriptor ownership, and
   presents headerless IP datagrams to sing-tun.
3. `sing-box-v1.13.15-dns-failover.patch` implements the bounded primary/fallback
   resolver contract required by the closed product projection.
4. `sing-box-v1.13.15-endpoint-conflict.patch` reports only exact mixed-listener
   and controller `EADDRINUSE` failures as structured conflicts while preserving
   ordinary startup and cleanup failures.

`LibboxPacketEngineFactory` and `LibboxProxyEngineFactory` now construct
`SourceBuiltLibboxRuntimeFactory`; `project.yml` links the same source-built
XCFramework into ProxyAgent and Packet Tunnel. The build records upstream and
patched module digests, combined patch digest, module verification, security
scan, build tags, tool identities, XCFramework tree hash, and the native
product manifests. The sing-box Apple client gitlink is reference material
only; its private packet-flow access is not copied.

The public packet contract has deterministic unit/integration coverage and can
be built into an unsigned arm64 Release graph. It is not yet a physical data-
plane verdict. Release still requires the exact signed and installed candidate
to prove IPv4/IPv6 TCP, UDP/QUIC, DNS, route/bypass, cancellation, backpressure,
stop/recovery, weak-network, throughput, resource, switch, and soak gates. If
those gates fail, there is no private-API, downloaded-core, root-helper, or
alternate-engine fallback.

## Evidence levels

- Source/unit: production composition, protocol bounds, state transitions,
  recovery rules, and error paths are inspected and tested without installed
  Apple identities.
- Unsigned candidate: Xcode and Tauri prove arm64 Release compilation,
  link/bundle layout, native-product manifests, and version/build bindings. It
  is intentionally non-runnable as a production identity graph.
- Signed-installed: the unchanged candidate must prove Developer ID identities,
  provisioning, entitlements, registration/approval, nested signatures,
  notarization, staple, and Gatekeeper with assessments enabled.
- Physical data plane: clean Apple Silicon runs on macOS 15 and current macOS
  must prove traffic, lifecycle, fast-user switching, crash/reboot recovery,
  performance, resource, and soak requirements.
- Publication: legal review, corresponding source, notices, SBOMs, signatures,
  hashes, and public URL verification are separate final gates. A local signed
  app is not publication proof.
