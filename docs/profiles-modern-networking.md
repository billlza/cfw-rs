# Modern network profiles in 0.4.0

Use Profiles → Import File for Clash YAML or a WireGuard `.conf` file.
WireGuard import supports one peer, a numeric IPv4/IPv6 interface address,
endpoint, MTU, keepalive, optional preshared key and up to two numeric DNS
servers. IPv4/IPv6 default-route AllowedIPs are preserved in the actual peer.
Multi-peer configurations, split AllowedIPs, search domains and wg-quick shell
hooks are rejected before saving; they are not silently discarded or executed.
Keys are extracted into the existing credential vault.

Clash `select` and `url-test` groups preserve their different selection behavior.
For automatic groups, the probe URL, interval and tolerance reach the runtime;
explicit zero tolerance remains zero. Interval is bounded to 30–86400 seconds.
An imported `fallback` group is not converted into a fastest-node group.
Clash `dialer-proxy` creates an outbound detour. All group and detour references
are checked together for cycles before import.

The JSON profile editor also accepts the following optional policies.
Existing profiles retain their canonical form when these fields are absent.
Changing a profile document follows the normal profile/credential replacement
transaction; saved node selections remain separate from that document.

## TLS 1.3 and hybrid key exchange

Add the following to the existing TLS object of a compatible TLS-based node:

```json
{
  "enabled": true,
  "server_name": "proxy.example.com",
  "min_version": "1.3",
  "curve_preferences": ["X25519MLKEM768"]
}
```

This requires the hybrid X25519/ML-KEM-768 exchange. A classical-only peer is
rejected. To permit classical compatibility explicitly, include `"X25519"`
as another curve. Certificate authentication remains the standard TLS
certificate mechanism; this option is not a claim of post-quantum certificate
signatures or provider-specific post-quantum WireGuard.

Explicit curves require standard TLS. The pinned uTLS/Reality adapters do not
honor those curve settings, so combining them is rejected. ECH requires
`min_version: "1.3"` and an enabled `ech` object containing `config`: an array
of public `ECH CONFIGS` PEM strings supplied by the server operator.
No ECH key file or implicit bootstrap DNS discovery is read.
Reality and ECH cannot be combined.

## DNS transports

The optional top-level `dns.servers` array accepts one primary resolver and one
optional fallback. Supported types are `udp`, `tcp`, `tls` (DoT), `quic`
(DoQ), `https` (DoH), and `h3` (DoH over HTTP/3). For example:

```json
{
  "dns": {
    "servers": [{
      "type": "https",
      "server": "1.1.1.1",
      "server_port": 443,
      "path": "/dns-query",
      "tls": {
        "enabled": true,
        "server_name": "cloudflare-dns.com",
        "min_version": "1.3"
      }
    }]
  }
}
```

Resolver dial addresses are numeric; the TLS name is verified separately.
Encrypted transports require certificate verification. DNS follows the
selected outbound. If the profile explicitly selects DIRECT, the runtime's
ordinary direct dialer is used. Proxy failure never causes a direct fallback.
UDP DNS inside a WireGuard connection is carried by that encrypted tunnel;
UDP DNS in a DIRECT profile is ordinary unencrypted DNS.

Clash DNS import preserves one or two numeric `nameserver` endpoints, a pair
of numeric `default-nameserver` bootstrap resolvers, `dns.ipv6`, exact hosts
IP mappings and blacklist fake-IP filters (exact names, `+.` suffixes,
`*.` single-level subdomains and `*` single-label hostnames). Unsupported DNS
policy fields are reported before saving.
Fallback filters, nameserver policies and hosts aliases remain unsupported.

Fake-IP applies to TUN and combined TUN/System Proxy mode. The app-owned IPv4
pool is `198.19.0.0/16`, separate from its tunnel interface subnet; the optional
IPv6 pool is `2001:2:ffff::/48`. Imported default Clash benchmark pools are
adapted to this network plan. Arbitrary custom pools require explicit support.
Exclusions and hosts get real answers. `dns.ipv6: false` returns an empty
successful AAAA answer. Fake-IP mappings persist in the tunnel owner's cache;
System Proxy alone does not publish fake addresses it cannot intercept.

## Reproduce protocol checks

After preparing the pinned toolchains and patched engine source, run:

```sh
CFW_RELEASE_RUST_TOOLCHAIN=private \
CFW_TOOLCHAIN_ROOT=/absolute/toolchains \
/bin/bash -p scripts/test_advanced_protocols.sh \
  /absolute/patched-sing-box-source 192.168.1.10
```

Use the test Mac's own IPv4 address. The checks create temporary authenticated
proxy/WireGuard servers and DNS/echo listeners. They use generated test keys
and a temporary certificate trust store, without changing macOS networking.
They verify real TCP/UDP payloads, automatic selection, multihop failure
behavior, DNS transports and policy, server-observed hybrid TLS/ECH and rejection paths
under the race detector. Installed System Proxy/TUN acceptance remains a
separate check.
