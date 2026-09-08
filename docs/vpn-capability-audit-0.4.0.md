# 0.4.0 VPN capability and CFW compatibility audit

Checked 2026-09-09 against the installed CFW 0.20.39 and the pinned sing-box
1.13.15 source. Build 40050 has not been frozen, signed or installed. This
document is a delivery checklist, not a declaration that runtime acceptance
has passed.

## Product gaps

The detailed historical comparison is in [the CFW audit](cfw-compatibility-audit.md).
The following gaps remain relevant to a replacement client:

| Capability | Current source | Acceptance required |
| --- | --- | --- |
| System Proxy and TUN together | Independent switches and combined owner mode | Installed OS readback, real traffic and cleanup |
| Full imported groups and ordered rules | Selectors and supported Clash rules; automatic URL-test groups added | Preserve group algorithm, selection and probe parameters; real automatic selection |
| Multihop | Validated outbound detours added | Both hops carry the connection; cyclic dependencies rejected |
| WireGuard | Single-peer userspace endpoint, Clash YAML and standard full-tunnel .conf import; vault references and build tags enabled | Component handshake, TCP/UDP and wrong-key checks passed; signed build must contain the same protocol and stack |
| TLS 1.3 hybrid key exchange | Explicit X25519MLKEM768 curves and TLS minimum added | Server-observed negotiated group; required mode rejects classical-only peer |
| Encrypted Client Hello | Inline public ECHConfigList accepted with TLS 1.3 | Server-observed ECH acceptance and rejection without plaintext fallback |
| Encrypted DNS | Configurable DoT, DoH, DoQ and HTTP/3; ordinary UDP/TCP also supported | All six transports passed real resolver exchanges; installed TUN DNS routing remains separate |
| Process/domain/IP split routing | Supported ordered rules and process lookup | Matching application traffic follows the configured rule |
| Core while OS switches are off | Missing | Independent local listener and controller lifecycle |
| DNS import and settings | Typed resolvers, WireGuard DNS, Clash exact hosts, bootstrap pair, DNS IPv6 and blacklist fake-IP filters | Source fallback filters, nameserver policies and system hosts remain gaps; installed packet routing requires verification |
| Provider subscriptions and fallback groups | Missing | Preserve refresh and failover semantics; do not translate fallback into fastest-node selection |
| Port, LAN binding, log level and TUN preferences | Incomplete | Persist settings, validate exposure and apply actual runtime changes |
| Online profile switching and subscription preferences | Incomplete | Transactional replacement, update options and recoverable failures |
| UI preferences, tray, shortcuts and SSID automation | Incomplete | Persist advertised controls and remove nonfunctional affordances |
| Scripting/mixin | Arbitrary execution is unsupported | Declarative configuration support needs a bounded extension model |

Old profiles retain their canonical representation when new optional fields
are absent. New policy fields change the profile identity and follow the
existing credential reprovisioning and profile replacement transaction.
Automatic groups cannot be overwritten with a saved manual selection.

Real component checks on September 9 passed with the race detector enabled:
server-observed X25519MLKEM768/TLS 1.3 and ECH; classical-only and ECH rejection;
UDP/TCP/DoT/DoH/DoQ/HTTP3 DNS replies; multihop entry failure; automatic selection;
and WireGuard TCP/UDP plus wrong-preshared-key rejection. DNS policy checks also
passed for exact hosts, fake-IP exclusions, CFW single-label wildcard semantics,
AAAA suppression, IPv4/IPv6 fake-IP pools and mapping persistence after restart.
These checks use the
Rust projection and the pinned core with temporary test servers.

They exposed and corrected unsynchronized URL-test selections, replacement of
explicit zero tolerance with the upstream default, and DNS startup refusal
when a DIRECT profile emitted an explicit empty-DIRECT detour. The dependency
repair publishes TCP/UDP choices as one immutable atomic snapshot; it does not
add a second health-check scheduler.

The Go vulnerability scan found zero reachable vulnerable symbols and zero
vulnerable imported packages. It also reported the unused
`golang.org/x/crypto/openpgp` module-level retirement advisory
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932). That package is not in the
product's imported graph; this is not described as a fixed upstream advisory.

## Current VPN technology references

| Technology | Official example | CFM implementation boundary |
| --- | --- | --- |
| Modern UDP tunnel and roaming | [WireGuard protocol](https://www.wireguard.com/protocol/) | Reuse the maintained engine implementation; a static preshared key is not a post-quantum key-exchange service |
| Post-quantum tunnel | [NordVPN NordLynx compatibility](https://support.nordvpn.com/hc/en-us/articles/30046321712529-NordVPN-Post-quantum-encryption-explained), [ExpressVPN Lightway](https://www.expressvpn.com/lightway) | Provider protocols require compatible servers; standard TLS hybrid exchange can protect supported TLS proxy transports |
| Traffic-analysis resistance | [Mullvad DAITA v2](https://mullvad.net/en/blog/2025/3/28/daita-version-2-now-available-on-all-platforms) | Coordinated padding algorithms and server support; ordinary packet padding cannot be described as DAITA |
| Multihop with automatic entry selection | [Mullvad multihop modes](https://mullvad.net/en/blog/introducing-multihop-modes) | Client detours require compatible entry/exit transports; server operator independence is not established by counting hops |
| Obfuscation and resilient protocol selection | [Proton Stealth](https://protonvpn.com/blog/stealth-vpn-protocol), [Proton protocol engine](https://protonvpn.com/blog/protun-technical) | Existing Hysteria2, TUIC, AnyTLS, Reality and supported transports are distinct protocols; they do not imply Proton service compatibility |
| Kill switch | [Proton kill-switch behavior](https://protonvpn.com/support/what-is-kill-switch) | Requires OS-enforced leak prevention during failures and restarts. A failed proxy connection or an Off state is not sufficient proof |
| TLS 1.3 hybrid exchange and ECH | [Pinned engine TLS options](https://github.com/SagerNet/sing-box/blob/v1.13.15/option/tls.go) | Required hybrid mode must use standard TLS and TLS 1.3. The pinned uTLS/Reality adapters do not apply explicit curve preferences |

Mullvad's August 24 multihop announcement makes a platform distinction: its
new modes are available on iOS, with Android and desktop rollout scheduled
later. Proton's protocol-engine article describes post-quantum cryptography as
future groundwork. Neither statement should be generalized into a currently
available macOS feature without checking the shipping client.

RAM-only server fleets, provider no-log policies, independently operated relay
networks, DAITA server coordination, commercial account provisioning and
provider-specific post-quantum negotiation cannot be supplied by a local
configuration switch. They require actual server implementations and service
access. No such capability is claimed by this package without that evidence.

## Security and verification scope

The transport changes protect network authentication, confidentiality and
metadata from on-path observation, including collection for later decryption.
They reuse existing protocol implementations and the existing credential
vault; no custom cryptographic protocol or additional file-signing mechanism
is introduced. ECH configuration is public configuration, not a secret.

Profile parsing, real engine forwarding, OS proxy/TUN operation, package
signing/notarization and public publication are separate results. Current CFW
network state must remain intact during isolated component tests. A candidate
is handed over only with its actual verification status and remaining gaps;
an older candidate's passing checks cannot validate changed source.
