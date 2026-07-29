# Profiles

Profiles are local typed application JSON documents whose supported protocol
fields mirror safe sing-box outbound shapes. `credential_ref` is an
application-owned non-secret extension that is removed during projection.
Stored profiles never contain Clash YAML, parsers, mixins, custom scripts,
PAC scripts, or executable/core installation fields. Subscription import
converts Clash Meta YAML `proxies` lists and node-URI bundles into this
schema at the boundary; everything outside the node list (rules, groups,
listeners, DNS) is owned by the app's projection and is not carried over.

The safe schema is intentionally closed:

- top-level `outbounds` is required and contains one to 128 entries;
- every outbound has a unique `tag` and a typed `direct`, `block`,
  Shadowsocks, VMess, VLESS/Reality, Trojan, or Hysteria2 shape;
- top-level `route` is optional and may contain only `final`;
- `route.final`, when present, must reference a declared outbound tag;
- remote server endpoints are bounded and typed, while profile-embedded
  subscriptions and remote resources remain disabled;
- credential-bearing outbounds contain canonical `credential_ref` objects;
  raw passwords, UUID values, private keys, and other secret fields fail
  validation;
- user-defined DNS/services, scripts, executable paths, and unknown fields
  fail validation.

This does not represent full sing-box protocol support. After import, the app
checks the native vault and requests only missing references. All missing
values are submitted atomically; they are never added to the profile, renderer
store, App Group, logs, or configuration digest. Credential references are
immutable: changing a secret requires a new UUID and profile update, while an
identical retry is idempotent. Explicit cleanup previews unused references and
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
