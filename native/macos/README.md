# CFW native macOS network boundary

This directory contains the macOS 15+, Apple Silicon-only boundary for the
network-stack migration. It is deliberately fail-closed: neither the packet
tunnel nor the proxy agent can enter an active state until the pinned,
source-built libbox adapter is linked.

## Layout

- `CFWSharedProtocol` owns versioned command/response DTOs, fixed configuration
  slots, digest validation, and user-context stores used by ProxyAgent. Those
  App Group and Data Protection Keychain stores are explicitly not a system
  extension transport.
- `CFWPacketTransport` bridges the public `NEPacketTunnelFlow` methods to a
  bounded nonblocking `SOCK_DGRAM` socketpair. It never accesses private object
  fields or file descriptors through KVC.
- `CFWAppleNetwork` is the host-side `SystemExtensions` and
  `NETunnelProviderManager` adapter. A tunnel is active only after the provider
  returns a matching generation and digest.
- `CFWPacketTunnel` contains the `NEPacketTunnelProvider`. Its production
  dependencies return `systemExtensionStateTransportNotLinked`, and its default
  engine factory returns `libboxNotLinked`; neither placeholder may ship.
- `CFWProxyAgent` is a non-root user agent. It validates the connecting user,
  then calls `NSXPCConnection.setCodeSigningRequirement` with the exact Team ID
  and host bundle identifier before exposing its typed XPC protocol. Foundation
  evaluates that requirement against the connection identity; no PID lookup or
private audit-token accessor is used.

Tunnel network settings bind the private-network bypass bit into the signed
configuration identity. When enabled, the provider excludes IPv4 loopback,
RFC1918 and link-local ranges plus IPv6 loopback, ULA and link-local ranges;
when disabled it publishes no such exclusions. DNS points only at
provider-owned virtual peers in reserved address space and captures the default
resolver domain. Release remains blocked until libbox is proven to service
those peers without an external resolver fallback.

The Xcode `CFWProxyAgent` product is a background-only, arm64 `.app`, suitable
for embedding as a signed user agent. `CFWProxyAgentCore` is the single static
module shared by that executable and its tests. Host embedding, launch-agent or
login-item registration, provisioning, and outer-app signing remain release
pipeline responsibilities; the unsigned validation build intentionally cannot
pass its Team ID identity policy.

System proxy activation is transactional. The engine must first report a
validated `127.0.0.1` mixed-listener endpoint. ProxyAgent then captures only the
HTTP, HTTPS, SOCKS, PAC-enable, and auto-discovery-enable fields for each enabled
network service, persists a prepared ownership journal, applies all changes in
one SCPreferences commit/apply cycle, verifies the result, and marks the journal
applied. The journal contains no credentials, PAC URL, scripts, or profile
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
the expected restored state.

The Rust coordinator remains the single writer of product intent. Swift state
objects are observations/wire DTOs, not a second product state machine. The
ProxyAgent may use its user-context acceptance cursor. The system extension
cannot: it must accept complete authenticated configuration over its global XPC
endpoint and maintain replay state in a root-owned global store. Likewise, the
user App Group `Engine/engine.lock` cannot arbitrate ProxyAgent against the
root-context system extension. A global, identity-bound lease protocol must
replace it before either production libbox adapter is enabled.
If a provider engine refuses to stop, the provider remains failed-but-owned and
retains the lease until an explicit stop retry succeeds. Canceling the tunnel
does not release that ownership; forced provider-process termination is the
final OS boundary that closes the lease descriptor.
Every start attempt must use a newer generation. A provider crash therefore
does not authorize an OS restart with the saved descriptor: the Rust
coordinator must observe the failure, persist the next generation, and start
again. This is an intentional fail-closed recovery contract.

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
`CFWPacketTunnelExtension` System Extension executable. This keeps one provider
implementation while allowing its pure lifecycle controller to be unit tested
outside a Network Extension process; the Info.plist names
`CFWPacketTunnel.PacketTunnelProvider` explicitly.

Tunnel descriptors carry explicit IPv6 and MTU options. IPv4 uses the RFC 2544
benchmarking subnet `198.18.64.1/30` with peer/DNS `198.18.64.2`; IPv6 uses the
RFC 5180 benchmarking subnet `2001:2:0:64::1/126` with peer/DNS
`2001:2:0:64::2`. These addresses are intentionally outside the LAN bypass
prefixes. Disabling IPv6 removes both the IPv6 default route and IPv6 resolver
from Network Extension settings.

## Build and test

Fast, unsigned validation:

```sh
swift test --package-path native/macos
```

Generate and validate the Xcode project:

```sh
cd native/macos
xcodegen generate
xcodebuild test \
  -project CFWNative.xcodeproj \
  -scheme CFWNativeTests \
  -destination 'platform=macOS,arch=arm64' \
  CODE_SIGNING_ALLOWED=NO
xcodebuild build \
  -project CFWNative.xcodeproj \
  -scheme CFWPacketTunnel \
  -destination 'platform=macOS,arch=arm64' \
  CODE_SIGNING_ALLOWED=NO
```

XcodeGen 2.45.4 adds a `ditto` phase for Swift static-library Objective-C
headers. Script sandboxing is disabled only on those three generated static
library targets because that generated phase cannot create its declared header
output under Xcode 26.6; it remains enabled for the Agent and System Extension
targets. No repository-authored build script receives this exception.

Signed activation additionally requires matching Developer ID provisioning for
`com.bill.clashformac`, `com.bill.clashformac.packet-tunnel`, the System
Extension/Network Extension capabilities, and the shared App Group. Never add a
development entitlement fallback.

The App Group entitlement may namespace authenticated IPC and provider-local
state, but it does not make the logged-in app and root system extension resolve
the same filesystem container. The Packet Tunnel target intentionally has no
user Keychain access-group entitlement.

Apple references:

- [Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [TN3134: Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Network Extension Provider Packaging](https://developer.apple.com/forums/thread/800887)
- [Installing system extensions and drivers](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers)

## libbox gate

`Dependencies.lock.json` pins sing-box `v1.13.14` at commit
`25a600db24f7680ad9806ce5427bd0ab8afe1114`, Go `1.26.5`, and gomobile
`v0.1.12`. The Apple client commit is reference material only and must not be
copied where it obtains a packet-flow file descriptor through KVC.

Before replacing `MissingLibboxEngineFactory`, the integration must prove that
the pinned libbox exposes a supported raw-packet FD contract compatible with
the public socketpair pump. The build must record Go module verification, build
tags, source commit, and XCFramework SHA-256. If that contract or the throughput
gate cannot be proven, the migration stops here; there is no private-API,
downloaded-core, root-helper, or alternate-engine fallback.

The current pinned Darwin implementation does not yet meet that contract:
after `OpenTun` it calls `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`, which
accepts a utun control socket rather than the pump's public
`AF_UNIX/SOCK_DGRAM` descriptor. A local source build therefore establishes
only build reproducibility, not packet-flow compatibility or tunnel readiness.
