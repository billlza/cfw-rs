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
Local JSON/YAML/text files and pasted node links use this same conversion
boundary, not a JSON-only import path. Source input is at most 512 KiB and
must be valid UTF-8; the converted profile retains its independent size limit.
Everything outside the node list (rules, groups, listeners, DNS) is owned by
the app's projection and is not carried over. The import page states this
limit before import; accepting a Clash YAML file does not mean its routing
behavior was preserved.

The safe schema is intentionally closed:

- top-level `outbounds` is required and contains one to 128 entries;
- every outbound has a unique `tag` and a typed `direct`, `block`,
  SOCKS5, Shadowsocks, VMess, VLESS/Reality, Trojan, Hysteria2, AnyTLS, or TUIC v5
  shape;
- top-level `route` is optional and may contain only `final`;
- `route.final`, when present, must reference a declared outbound tag;
- remote server endpoints are bounded and typed, while profile-embedded
  subscriptions and remote resources remain disabled;
- credential-bearing outbounds contain canonical credential reference objects;
  single-secret types use `credential_ref`, while raw passwords, UUID values,
  private keys, and other secret fields fail validation;
- SOCKS5 supports anonymous access or a complete username/password pair,
  IPv4/IPv6/domain endpoints, and TCP/UDP. Its optional `authentication` object
  contains `username_credential_ref` (`socks5_username`) and
  `password_credential_ref` (`socks5_password`); both values are 1..=255 UTF-8
  bytes without control characters. Projection emits sing-box `type: socks`,
  `version: 5`. Optional `network: tcp` or `network: udp` restricts transport;
  omission enables both. `socks://` and `socks5://` links accept anonymous,
  percent-encoded plain, or base64 username/password userinfo, with an explicit
  port. Clash `type: socks5` preserves `udp: false` (including its default) as
  TCP-only; `udp: true` permits both. Upstream sing-box `type: socks` accepts
  version 5 or its omitted default. SOCKS4/4a, SOCKS-over-TLS and UDP-over-TCP
  are rejected rather than silently downgraded. Ordinary SOCKS5 does not encrypt
  its authentication or transport;
- TUIC carries separate `uuid_credential_ref` and `password_credential_ref`
  values. Hysteria2 and TUIC use QUIC TLS and reject uTLS and Reality, while
  AnyTLS may use the standard TLS schema including those extensions. Runtime
  projection fixes the minimum TLS version at 1.2, normally negotiates TLS 1.3,
  and explicitly disables TUIC 0-RTT. QUIC always uses TLS 1.3; profiles cannot
  lower the TLS floor or enable 0-RTT;
- V2Ray QUIC requires enabled standard TLS and rejects uTLS/Reality. VLESS
  Vision cannot use a V2Ray transport stream and accepts only omitted or XUDP
  packet encoding;
- Reality requires an enabled `tls.utls` fingerprint, imported from Clash
  `client-fingerprint`, URI `fp`, or sing-box `tls.utls`. sing-box runs
  Reality only over uTLS, so a node without one fails at import instead of at
  engine start; no fingerprint is chosen on its behalf;
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

Imported inline credentials are committed through the same native vault-first
transaction for local and remote sources. A refused, unknown, or mismatched
vault result does not expose a partially imported profile. Local canonical
reference-only JSON retains the explicit manual-provisioning workflow; remote
reference-only subscriptions must still confirm the existing vault audience.
The file picker and drag-drop accept `.json`, `.yaml`, `.yml`, and `.txt`.
Excel is not a profile format: use its node link or accompanying YAML/JSON.

Profile cards show the stored display name, source type (`local file` or
`subscription`), and time since the document was saved in this application.
The green marker identifies the selected profile. Source type is derived from
the existing envelope during the repository snapshot; it does not require
opening each profile, expose a subscription URL, or change the storage schema.
Document byte size is available in profile details and is not presented as
traffic or subscription quota. CFW keeps its display names in a separate
`profiles/list.yml` index: importing an individual YAML file supplies its file
name, so its CFW display name must be supplied explicitly or changed in profile
Settings. The time shown is not the age recorded by CFW.

Application-managed storage is also bounded and fail closed: each complete
profile envelope is at most 384 KiB, the repository contains at most 4,096
entries and 512 unique credential references, and all envelopes together
contain at most 256 MiB. Listing and
importing validate every existing entry under the repository lock; malformed,
linked, oversized, or unexpected entries are reported instead of skipped.
Selection is a separate private, versioned record bound to the profile digest.
Proxy or Tunnel start fails when selection is absent, missing, stale, or names
an invalid profile; turning the engine Off never depends on profile state.

An intact entry whose document, provider sources or saved node selections
fail the current validation, such as a Reality node an earlier version stored
without uTLS, is not corrupt. It is listed under its name as invalid, with the
validator's message, and does not block the other profiles: they can still be
imported, selected and started. An invalid profile cannot be selected, edited,
updated, exported or started, and no other profile is chosen in its place.
Delete removes it. For a subscription, the card shows the subscription URL on
request, with a Copy button, so it can be imported again first; the list
itself still carries no URL. The envelope is checked as strictly as any other:
an unsafe or linked file, an oversized or non-canonical envelope, or a stored
document that no longer matches its digest still blocks the repository with
that error. If the selected profile is invalid, the list shows it as selected;
System Proxy, TUN, runtime settings and the configuration preview report its
validation error until another profile is selected or it is deleted. Deleting
it requires the core to be stopped and leaves no profile selected. Credential
cleanup is refused while any invalid profile is listed, naming each one,
because a document that does not validate yields no credential references;
its Keychain items stay until it is deleted and cleanup runs.
