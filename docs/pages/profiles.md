# Profiles

Profiles are local typed application JSON documents whose supported protocol
fields mirror safe sing-box outbound shapes. `credential_ref` is an
application-owned non-secret extension that is removed during projection.
Stored profiles never contain Clash YAML, parsers, mixins, custom scripts,
PAC scripts, or executable/core installation fields. Subscription import
converts restricted upstream sing-box `outbounds` JSON, Clash Meta YAML
`proxies` lists, Shadowsocks SIP008 JSON, and node-URI bundles into this schema
at the boundary. VMess links may use either traditional base64 JSON or the
URL-shaped AEAD form; URL-shaped VMess has no legacy `alterId` path.
everything outside the node list (rules, groups, listeners, DNS) is owned by
the app's projection and is not carried over.

The safe schema is intentionally closed:

- top-level `outbounds` is required and contains one to 128 entries;
- every outbound has a unique `tag` and a typed `direct`, `block`,
  Shadowsocks, VMess, VLESS/Reality, Trojan, Hysteria2, AnyTLS, or TUIC v5
  shape;
- top-level `route` is optional and may contain only `final`;
- `route.final`, when present, must reference a declared outbound tag;
- remote server endpoints are bounded and typed, while profile-embedded
  subscriptions and remote resources remain disabled;
- credential-bearing outbounds contain canonical credential reference objects;
  single-secret types use `credential_ref`, while raw passwords, UUID values,
  private keys, and other secret fields fail validation;
- TUIC carries separate `uuid_credential_ref` and `password_credential_ref`
  values. Hysteria2 and TUIC use QUIC TLS and reject uTLS and Reality, while
  AnyTLS may use the standard TLS schema including those extensions. Runtime
  projection fixes the minimum TLS version at 1.2, normally negotiates TLS 1.3,
  and explicitly disables TUIC 0-RTT. QUIC always uses TLS 1.3; profiles cannot
  lower the TLS floor or enable 0-RTT;
- V2Ray QUIC requires enabled standard TLS and rejects uTLS/Reality. VLESS
  Vision cannot use a V2Ray transport stream and accepts only omitted or XUDP
  packet encoding;
- HTTP/H2 preserves a bounded method/path/Host shape. Mihomo `http-opts` with
  one deterministic path and Host authorities is accepted; multiple path
  alternatives and arbitrary custom headers are rejected instead of dropped;
- Hysteria2 port hopping stores only canonical non-overlapping port/range
  entries and an optional fixed 1..=3600-second interval. Projection emits the
  pinned sing-box 1.13 `server_ports`/`hop_interval` fields; randomized
  Mihomo intervals remain a visible unsupported error;
- Shadowsocks 2022 URI import follows SIP002's plain percent-encoded userinfo
  form; Base64 userinfo and legacy whole-link envelopes are rejected for 2022
  methods. Every colon-delimited PSK is canonical standard Base64 and has the
  method's exact 16- or 32-byte decoded length before vault staging;
- user-defined DNS/services, scripts, executable paths, and unknown fields
  fail validation.

This does not represent full sing-box protocol support. After import, the app
checks the native vault and requests only missing references. All missing
values are submitted atomically; they are never added to the profile, renderer
store, App Group, logs, or configuration digest. Credential references are
immutable across profile audiences: changing a secret requires a new UUID and
profile update, while an identical retry is idempotent. Explicit cleanup previews unused references and
revalidates both the full managed-profile snapshot and Keychain revision before
atomic deletion. Installed-signature, entitlement, and physical runtime proof
are still required before release. A rejected profile is shown as an error; it
is never converted to an empty/default profile.

Application-managed storage is also bounded and fail closed: each complete
profile envelope is at most 384 KiB, the repository contains at most 4,096
entries and 512 unique credential references, and all envelopes together
contain at most 256 MiB. Listing and
importing validate every existing entry under the repository lock; malformed,
linked, oversized, or unexpected entries are reported instead of skipped.
Selection is a separate private, versioned record bound to the profile digest.
Proxy or Tunnel start fails when selection is absent, missing, or stale;
turning the engine Off never depends on profile state.
