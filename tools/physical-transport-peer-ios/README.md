# Test-only iOS physical transport peer

This directory contains validation infrastructure for a macOS-only CFM
product. The app is not an iOS CFM client, is not included in the macOS native
project, Cargo workspace, DMG, or release bundle, and must not be presented as
an iOS compatibility surface.

The foreground-only app exposes three fixed Wi-Fi listeners:

- TCP/IPv4 sink on `44333`, with the existing LAN-peer limits: at most 64
  request bytes and five seconds per connection.
- TLS 1.3 framed echo on `44334`, ALPN `cfm-transport-peer-tls/1`.
- QUIC/TLS 1.3 framed echo on `44335`, ALPN
  `cfm-transport-peer-quic/1`.

TLS and QUIC disable tickets, resumption, and TLS False Start. The app has no
Network Extension, VPN, App Group, Keychain group, background networking,
multicast entitlement, shell, subprocess, arbitrary port, or arbitrary command
surface. Entering the background stops the peer and is a failed run.
The three listeners share one session-wide limit of eight connection attempts;
there is no unbounded sequence of short-lived accepted connections.
Those attempts are independent logical probes. The iPhone QUIC listener uses
an explicit `NWConnectionGroup` and admits exactly one client-initiated
bidirectional stream (ID 0). The controlled Mac producer uses Network.framework's
single-stream QUIC `NWConnection` API and advertises zero server-initiated
streams. The server-side QUIC group counts as one global probe attempt; its
child stream does not consume a second attempt. A second tunnel or stream fails
the run instead of being treated as another service connection.
Tunnel establishment, first-stream arrival, and stream TLS readiness share one
absolute seven-second deadline; the budget is not reset between those stages.
The ready receipt includes exactly one RFC1918 IPv4 address from the active
`en0` Wi-Fi interface; cellular, tunnel, link-local, public, ambiguous, and
IPv6-only endpoint states fail closed for this LAN-only pilot.

The host creates a fresh P-256 identity in a private empty directory by running
`certgen` with no arguments. The app accepts only canonical `session.json`,
`certificate.der`, and `private-key.x963` files in its fixed Documents
subdirectory. It verifies both digests, creates an in-memory `SecIdentity`, and
deletes both identity files before any listener becomes ready. Ready and result
receipts are canonical, bounded JSON files; they contain digests, typed
observations, and counters, not payloads, raw device identifiers, provisioning
profiles, or private keys. A result is explicitly
`server_observation_only` and `claim_eligible=false`. Its status records a
closed, pair-required, or failed shutdown/evidence boundary; no single peer
result is a test-success declaration.

Secure QUIC completion is drained in ownership order: the server sends the
delivery confirmation in a final content context, observes the controlled Mac
terminate that stream after exact 5A plus EOF, then cancels and observes the tunnel.
At this post-confirmation drain boundary, Network.framework may report either
`cancelled` or `failed` on the child stream, and a direct Mac QUIC close may
surface the tunnel's `failed` callback first. These terminal shapes are only a
local `pair_required` candidate after final 5A processing; the joint verifier
still requires the Mac's exact 5A plus clean EOF receipt.
Final cleanup additionally waits for all three listener
cancellation callbacks, so `listeners_closed=true` covers the QUIC tunnel as
well as the listening sockets.

## Two-stage local-network primer

A fresh install must first be launched with the single fixed argument
`--cfm-local-network-primer-v1`. This explicit mode never constructs
`PeerPaths` or `PeerIdentity` and therefore never reads or deletes the TLS
session inputs. It starts TCP/IPv4 port `44332` on Wi-Fi and advertises only
`_cfm-primer._tcp` with automatic renaming disabled. The primer cancels the
listener only after both the listener-ready callback and the matching Bonjour
registration callback have been observed. It writes a canonical, write-once
`Documents/CFMTransportPrimer/primer-result.json` only after the listener's
actual cancelled callback.

The iOS permission sheet can suspend and exit the foreground-only primer before
registration completes. A bounded host retry may reuse only the same empty,
0700, app-owned primer directory; any file, symlink, owner, or mode drift fails
closed. The primer also refuses to start if the transport-session directory
exists, so no transport identity can exist during either primer attempt.

The transport launch reopens the canonical primer receipt through a no-follow
file descriptor and requires an app-owned `0600` file no older than 15 minutes
before it reads or consumes the TLS identity. This app-side gate is independent
of the host transaction checks.

## Packet-LAN evidence mode

The separate `--cfm-packet-lan-run-v1` launch mode is the active test peer for
the macOS Packet `lan-bypass` case. It consumes one canonical
`Documents/CFMPacketLanPeer/session.json`, tightens CoreDevice's exact copied
directory mode from `0755` to `0700` on the same inode, removes the session
file, and publishes a fresh `en0` RFC1918 ready address for TCP/IPv4 port
`44333`. The address is never stored in the endpoint policy.

Wireless CoreDevice can show the paired phone as dormant between commands.
The host therefore uses the list only for dual-hash selection, requires the
following details receipt to prove `connected` and `preparednessState=7`, and
rechecks the unlocked state immediately before both the primer and Packet
launches. The operator must keep the physical iPhone unlocked and its screen
awake for the complete run; a locked launch is a hard failure and is followed
by owned-app cleanup, never a retry or silent fallback.

Exactly three non-overlapping connections are admitted in `start`, `target`,
and `end` order. Each must deliver one distinct 20-byte session token followed
by TCP EOF, and each must use a distinct client ephemeral port. The result is
still `server_observation_only` and `claim_eligible=false`; the macOS validator
must match every server tuple and token digest to the sender receipt and pcap,
then prove exact PID termination, owned-app uninstall, and final app/process
absence. This mode does not expose TLS/QUIC services and does not turn the app
into an iOS VPN client.

The primer receipt proves those limited lifecycle observations; it does not
claim that iOS exposes a programmatic Local Network authorization result and is
always `claim_eligible=false`. The host must copy and validate that receipt,
bind its PID to a full process inventory, terminate that exact PID, and prove
process absence before copying `Documents/CFMTransportPeer` and launching the
normal session mode with the sole argument `--cfm-transport-run-v1`. An empty
argument list or any unknown application argument fails before either mode
touches files or the network.

## Offline verification

Generate the Xcode project with the repository-pinned XcodeGen and compile the
unsigned device build:

```sh
target/toolchains/xcodegen-2.46.0/bin/xcodegen generate \
  --spec tools/physical-transport-peer-ios/project.yml \
  --project tools/physical-transport-peer-ios
xcodebuild \
  -project tools/physical-transport-peer-ios/CFMPhysicalTransportPeerIOS.xcodeproj \
  -scheme CFMPhysicalTransportPeer \
  -configuration Debug \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO \
  build
swift test --package-path tools/physical-transport-peer-ios
```

These commands do not install or launch an app. A later physical pilot must use
one exact source-pinned device, refuse a pre-existing bundle ID, verify signing
and the installed process, require manual Local Network approval, and prove
termination and uninstall before its evidence can be considered. It must not
stop, modify, or delete the existing CFW installation.

The host-side lab contract pins CoreDevice management to its observed,
manually paired `localNetwork` control transport; `wired` and unknown values
are rejected rather than used as fallbacks. That control path is not data-plane
evidence: the ready receipt, Mac route check, and probes independently require
the peer endpoint on `en0` Wi-Fi and reject tunnel or non-private routes.

Generic TLS/QUIC echo proves only the named transport and exact application
bytes. It does not by itself prove AnyTLS, Hysteria2, TUIC, HTTP/3, or CFM iOS
support. For each secure positive probe, the Mac validates the exact framed
echo and then sends one fixed final delivery-acknowledgement byte. The final
`a5` uses Network.framework's final content context. On each TLS or QUIC probe
byte stream, the peer requires the exact acknowledgement and `isFinal=true`
before submitting its fixed confirmation byte in a complete, non-final content
context. It then waits for the local `5a` send completion, removes the old
connection from admission, and gracefully cancels it; that cancellation is the
sole source of the peer-visible EOF. This ordering prevents TLS or QUIC from
making the Mac eligible to start its next probe before the old connection has
left admission. TLS 1.3 does not surface the incoming final context as
`isComplete=true` until this close, so waiting for read completion before the
reply would deadlock. The iPhone v5 receipt therefore records
`delivery_acknowledgement_final_context_observed=true` and
`peer_terminal_observed=false` for secure probes; only the plain TCP sink uses
the latter field for a clean peer EOF. The Mac must validate the exact `a5`/`5a`
exchange and observe the final confirmation stream complete, so an interrupted
or truncated confirmation cannot be promoted.

The Mac and iPhone receipts separately record application-frame counts,
acknowledgement bytes, and confirmation bytes submitted or observed. A lab pass
requires the host joint verifier to recompute each session-derived payload and
match the canonical Mac v3 and iPhone v5 results on session, certificate,
process, transport, TLS 1.3 metadata, ALPN, early-data state, exact `a5`/`5a`
values, the explicit final-confirmation stream-complete flag, and all four byte
directions. Only that joint verifier may resolve the exact
`pair_required`/`processed` server result; a hard
failed result is never upgradable. Either receipt by itself remains
insufficient. The iPhone v5 result also records a bounded failed service,
failure reason, and last reached phase so a fail-closed transport race is not
collapsed into an unactionable generic error. An admission-overlap failure
additionally binds the blocking service, its connection phase and admission
sequence, the incoming sequence, whether the callback reused the same
`NWConnection` object, and the blocking QUIC stream identifier when it was
already observable. Non-overlap receipts encode all six diagnostic fields as
explicit `null`; partial or unbound observations are rejected. Earlier iPhone
result versions have no compatibility path.

This is a controlled-producer lab contract, not an authenticated protocol for
arbitrary local peers. Network.framework's `isFinal` marks the received content
context; it does not independently prove that a malicious sender placed no
additional bytes in that context. The joint verifier therefore relies on the
bundled Mac v3 producer, its exact byte counts, and its clean-EOF observation.
Schema versions distinguish contract shapes but do not authenticate who wrote
a receipt. A threat model that includes a malicious local receipt producer
would require an outer executable/source identity binding rather than treating
the version number or `isFinal` flag as anti-forgery evidence.

The peer gives a connection four seconds to reach validated security metadata.
Once security is ready, each explicit payload and delivery progress transition
renews a separate seven-second deadline. A deadline before delivery tracking
first removes the connection from the peer's live set and then immediately
disconnects it. The Mac waits eight seconds, so either peer deadline must resolve
before the next attempt. Network.framework does not guarantee that an incomplete
TLS handshake observes the peer-side disconnect. Therefore, only the three
explicit negative handshake checks may record that the connection did not reach
ready within the bounded Mac window and that the client sent zero bytes. This is
not proof that the remote peer received or rejected the handshake; the wrong-leaf
check separately requires its exact verification callback evidence. Any new peer
admission while another connection remains live is a sticky typed failure, so a
bounded negative observation cannot hide connection overlap. Deadlines in the
zero-frame and all positive paths remain hard failures. Normal completed
connections still use graceful cancellation, and the final overlap guard remains
fail-closed.
