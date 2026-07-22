# Public Packet Tunnel feasibility gate

The macOS data plane is a Packet Tunnel System Extension deployed through
Network Extension. The previous root LaunchDaemon/helper design is retired.

## Prototype requirement

The first native milestone uses a fixed DIRECT configuration and must prove on
physical Apple Silicon hardware:

- System Extension installation, approval, denial, pending state, replacement,
  restart-required behavior, and uninstall cleanup;
- a public `NEPacketTunnelFlow` packet pump with bounded buffering and
  backpressure;
- IPv4, IPv6, TCP, UDP/QUIC, DNS, stop, sleep/wake, path-change recovery, and
  provider crash behavior;
- throughput at least 90% of the same-machine libbox baseline with no more than
  10% added latency.

The pinned libbox must expose a documented/supported packet contract compatible
with this pump. If correctness or performance cannot be proven, implementation
stops and reports the blocker. It must not access a private
`packetFlow.socket.fileDescriptor`, use KVC, modify routes directly, or revive
the root helper.

## Current feasibility result

The pinned source builds as an arm64 XCFramework, but its current Darwin
platform contract is not compatible with the public packet pump. After
`PlatformInterface.OpenTun` returns a descriptor,
`experimental/libbox/service.go` immediately queries its tunnel name;
`experimental/libbox/tun_name_darwin.go` implements that query with
`getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`. That operation requires a real
utun control socket. The public adapter intentionally supplies one end of an
`AF_UNIX/SOCK_DGRAM` socketpair, so it cannot satisfy this contract.

Accordingly, the real libbox factory and Host Bridge remain absent and release
builds fail closed. Work may resume only with a narrow, source-audited libbox
raw-packet transport API that preserves packet framing, cancellation, bounded
backpressure, and ownership without private Network Extension access. The
correctness and 90% throughput gates have not been run and cannot be inferred
from the successful XCFramework build.

A second deterministic blocker exists at the process boundary. Developer ID
distribution uses a Network Extension system extension, which runs globally as
root. It therefore resolves an App Group container under the root home rather
than the logged-in app's home and cannot use the Data Protection Keychain. The
prototype's user App Group configuration file, shared `engine.lock`, and
Data-Protection-Keychain acceptance cursor cannot cross that boundary. The
production provider now reports `systemExtensionStateTransportNotLinked`
before touching those user-context stores.

Work may resume only after configuration, replay state, and cross-mode lease
ownership are redesigned around the named, authenticated system-extension XPC
endpoint (or another documented global-context mechanism), including explicit
multi-user arbitration. Provider secrets must be owned in the file-based
System Keychain; a user Keychain access group is not a fallback.

This boundary follows Apple's [Network Extension Provider Packaging](https://developer.apple.com/forums/thread/800887)
guidance for system-extension App Groups, XPC, multi-user operation, and
Keychain access, together with [TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).

## Packaging requirement

Developer ID distribution embeds the `.systemextension` in
`Contents/Library/SystemExtensions`. The app and nested extension require
matching Team ID, provisioning, App Group, and Network Extension entitlements.
All nested objects are signed before their parent, followed by notarization,
staple validation, and Gatekeeper validation.

The Swift prototype in `native/macos` is intentionally fail-closed until a
source-built libbox adapter is linked. Its existence does not establish a live
or releasable tunnel.
