# 0.4.0 UDP / DNS reliability changes

The measurements below describe the earlier sing-box 1.13.15 baseline. The
1.14.1 successor retains these fixes through the new pinned patch set; see
[the dependency refresh](dependency-refresh-20260915.md).

Verified on macOS/arm64 on 2026-09-14. These are source and component-build
results. The installed application remains build 40060; its signed identity and
the user's current network session have not been changed by this work.

## Defects and resulting behavior

| Defect | Evidence before the fix | Result |
| --- | --- | --- |
| SOCKS setup ignores cancellation after TCP connects | Cancellation failed at method negotiation, authentication and the SOCKS request, for both TCP and UDP. A 100 ms connect timeout did not stop a stalled handshake within 600 ms. | Each setup attempt owns a bounded cancellation scope. Its sockets close on cancellation or setup timeout; ownership transfers after success. Later cancellation of the initiating request cannot close the established connection. |
| A timed-out SOCKS UDP setup retains the DNS pool's pending dial | The first query timed out, its TCP control connection remained open, and the next query through the same DNS transport also timed out. | The failed dial returns and closes its control socket. The same DNS transport reconnects and answers two subsequent queries using one reusable UDP session. |
| SOCKS servers returning wildcard UDP relay addresses are not interoperable | A recording detour observed `0.0.0.0` or `::` as the relay destination. | Preserve the returned port and use the SOCKS server address. Direct connections use the actual control peer; detours preserve the logical final server instead of accidentally selecting an earlier hop. Explicit relay addresses remain intact; port zero is rejected. |
| SOCKS UDP inbound cleanup races with packet-connection wrapping | The race detector reported a read in `HandleConnectionEx.func1` concurrent with replacement of `socksPacketConn` in `HandleConnectionEx`. | Pin `github.com/sagernet/sing` to v0.8.12. The upstream fix captures the original association separately from the wrappers used by forwarding. |

The dependency change from `ef2df370afca` to
[`b631c8a7f9d59f31dc16be4b1d8b2904037a0046`](https://github.com/SagerNet/sing/commit/b631c8a7f9d59f31dc16be4b1d8b2904037a0046)
contains one commit, changing only `protocol/socks/handshake.go` (three added
lines and two removed lines). The module's own `go.mod` checksum is unchanged.
The sing-box engine remains pinned to v1.13.15.

## Implementation and build binding

`native/macos/patches/sing-box-v1.13.15-socks-lifecycle.patch` wraps the existing
SOCKS client without replacing its protocol parser. Setup attempts have separate
resource ownership; the wrapper installs no global connection registry and no
permanent socket deadlines. Authentication failures stay failures.

The existing dependency patch pins the upstream race fix. The sixth source patch
and both updated Go input hashes are bound in the dependency lock, patched-source
verification, native artifact metadata and the application's Rust build checks.
The module-cache test closure now includes the SOCKS package with race detection.
Old frameworks cannot satisfy the new metadata contract.

## Verification

The isolated Go tests use real local TCP/UDP sockets, not mocked success values.
They cover cancellation at six handshake boundaries, the configured timeout,
DNS recovery, wildcard and explicit relay addresses, zero-port rejection,
authentication failure, concurrent-session isolation, and datagrams of 1, 512,
1232 and 2048 bytes after the setup context has ended.

The extended `scripts/fixtures/advanced_dns_probe.go` uses the real Rust profile
projection and engine. Each of UDP, TCP, DoT, DoH, DoQ and HTTP/3 DNS is exercised
both directly and through an authenticated SOCKS relay. Each case performs three
uncached exchanges, cancelling each request context before the next exchange.
The DoQ fixture now serves multiple streams on the same connection; its earlier
single-stream implementation could not validate reuse.

The broader protocol fixture also checks TLS hybrid key exchange and ECH,
rejection of unsupported required cryptography, authenticated DNS fallback,
rejection when both DNS certificates are invalid, DNS policies and persistence,
multihop entry failure, automatic node selection, and WireGuard TCP/UDP and
wrong-key rejection. These TLS fixture settings do not change or redefine the
product's default TLS minimum.

Actual commands and full outputs are retained outside the repository under
`/Users/bill/cfw-release-history/dns-udp-20260914/`:

- `socks-regression-red-v2.log`: old implementation fails the target behaviors.
- `runtime-regression-v4.log`: affected Go packages pass with `-race`.
- `advanced-protocols-v5.log`: preserved upstream UDP cleanup race.
- `advanced-protocols-v6.log`: all 24 protocol checks pass with `-race`, including
  the 36 uncached DNS exchanges.
- `runtime-vet-final.log` and `protocol-fixture-vet-final.log`: Go vet results.
- `integration-tests-final.log`: 271 final source/artifact/build-contract tests pass.
- `host-build-check.log`: Rust host build script formatting and `cargo check`.
- `libbox-build-v2.log`: final macOS/arm64 framework build with the fixed dependency.
- `libbox-artifact-verification-final.log`: the 26-field artifact contract and
  patched-source identity pass; framework tree SHA-256
  `4d466aa05bc32c30200da3a8a006301772213ed8aedbdc2f683b52149c0a04b4`.
- `network-before.json` and `network-after.json`: unchanged CFW processes, system
  proxy, DNS configuration and VPN status.

Earlier harness failures, missing offline dependencies and the framework built
before the inbound race was discovered are retained. They are not acceptance
evidence for the final implementation.

## Remaining acceptance

This work does not establish sustained video throughput, real TUN restart
behavior, roaming performance, or superiority to Shadowrocket/Mihomo on the
same device and network. Those require an installed candidate and controlled
traffic measurements. No claim of a new installed or publicly released build
is made by these component results.
