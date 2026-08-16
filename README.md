# Clash for Mac (`cfw-rs`)

Clash for Mac is an Apple Silicon-only network client for macOS 15 and newer.
The target data plane is a source-built sing-box/libbox engine behind Apple
Network Extension APIs. The retired root-helper, mihomo, clash-rs, downloaded
core, Clash REST/WebSocket, custom-script, and PAC execution paths are not
release fallbacks.

## Architecture

```text
Tauri UI
  -> cfw-application::EngineModeCoordinator
     -> System Proxy: signed user ProxyAgent -> libbox mixed inbound
     -> Tunnel: Host Bridge -> NETunnelProviderManager
                            -> Packet Tunnel System Extension -> libbox
```

- `cfw-engine-api` owns versioned engine types and native boundary messages.
- `cfw-singbox-config` validates a typed app-owned profile schema using safe
  sing-box outbound field shapes and creates deterministic native projections.
- `cfw-application` serializes all mode transitions. Proxy and Tunnel always
  transition through Off and never fall back to the retired engine.
- `cfw-apple-network` is the Rust-facing Apple adapter boundary.
- `native/macos` contains the Swift 6 Host Bridge, signed user ProxyAgent,
  Packet Tunnel System Extension, shared protocol, and bounded public
  `NEPacketTunnelFlow` packet pump.

System Proxy and Tunnel are mutually exclusive. A mode is active only when the
observed runtime identity, generation, configuration digest, and readiness all
match the requested projection.

The profile validator implements a closed typed subset: one to 128 uniquely
tagged `direct`, `block`, Shadowsocks, VMess, VLESS (including Reality),
Trojan, or Hysteria2 outbounds, plus an optional `route.final` naming a
declared tag. Persistent JSON contains canonical `credential_ref` objects,
never passwords, UUID values, private keys, or other secrets. Projection emits
only empty credential placeholders and closed injection slots. User-defined
DNS/services, remote resources inside profiles, scripts, executable paths, raw
credentials, and unknown fields are rejected. Subscription import is a
boundary conversion into that schema: typed profile JSON passes through, and
Clash Meta YAML `proxies` lists and node-URI bundles (`ss://`, `vmess://`,
`vless://`, `trojan://`, `hysteria2://`) are converted with bounded parsers
whose secrets go straight to the credential vault, never into the stored
profile. Credential entry
queries only missing references and submits them as one bounded, zeroized
batch to the immutable shared-Keychain vault. Existing UUIDs are not
re-prompted; same-value retries are idempotent and rotation requires a new UUID
plus a profile update. Two-phase, revision-bound garbage collection removes
only entries absent from every selected or staged managed profile. Signed
entitlement and physical runtime proof remain release gates, so current source
must not yet claim a credential-bearing data plane can start in a release
build.

## Current implementation boundary

The repository fails closed while the native data plane is being completed.
The legacy privileged TUN path cannot start a core; its one-release tombstone is a non-operational unregister descriptor
exists only to remove the old control session and unregister the old service.
Launching 0.4.0 never runs that tombstone. Startup performs only a read-only
re-verification when a completed retirement marker already exists; otherwise
the current VPN remains untouched while a replacement profile is staged in a
separate native-profile directory. The one-way cutover requires an explicit
user confirmation and is rejected before any network mutation unless the
selected replacement profile and signed native data plane pass preflight.
Legacy System Proxy and DNS retirement is verification-first. If ownership or
the current value is ambiguous, migration reports a manual-cleanup action and
requires explicit user review instead of rewriting a user or administrator
setting.

The Swift Network Extension foundation and packet-pump tests are present, but a
release is blocked until all of the following are proven:

- authenticated global-context XPC replaces the invalid user App Group file,
  Data Protection Keychain cursor, and cross-context file-lock assumptions;
- the host and ProxyAgent share a dedicated credential Keychain access group;
  Tunnel secrets cross authenticated Host XPC only in memory for authority-side
  injection, and no secret enters an App Group, journal, log, or public digest;
- missing-only provisioning, presence queries, in-memory injection, and
  revision-bound garbage collection pass under the installed signed identities;
- the pinned libbox source exposes a supported packet contract compatible with
  the public packet pump;
- the libbox adapter replaces the explicit `libboxNotLinked` failure in both
  ProxyAgent and Packet Tunnel targets;
- Developer ID identity, Network Extension provisioning, System Extension
  approval, signing, notarization, staple, and Gatekeeper checks pass on clean
  macOS 15 and current macOS Apple Silicon machines;
- real IPv4, IPv6, UDP/QUIC, DNS, route, weak-network recovery, throughput,
  resource, and soak gates pass.

Engine DNS projection does not use the host resolver. In both System Proxy and
Tunnel, numeric direct bootstrap servers are referenced only while resolving a
domain-named proxy endpoint. Every ordinary engine query and route-level
destination lookup uses certificate-verified DoH detoured through the selected
outbound; Tunnel additionally hijacks packet-flow port 53 into that same
authenticated path. This is acyclic because authenticated DoH endpoints are
numeric and the selected outbound's own domain endpoint has an explicit direct
bootstrap pair. The pinned source patch gives both roles one bounded fallback
for rejected responses or transport errors. Each resolver is attempted at most
once, cancellation never triggers fallback, and two failures preserve both
causes. A source-built libbox carrying that patch and physical capture proof
remain release blockers; upstream sing-box 1.13 without the patch must not be
described as providing this failover.

There is no private-API or old-helper fallback if one of these gates fails.

## Pinned toolchain and dependencies

Release inputs are recorded in
[`scripts/dependency_pins.env`](./scripts/dependency_pins.env). Important pins:

- Rust 1.97.1
- Node.js 24.18.0 LTS
- Go 1.26.5
- SagerNet gomobile v0.1.13
- cargo-deny 0.20.2
- sing-box/libbox v1.13.15 at
  `3708fa18766cda1f11b77f6ed9c7bd61688f17df`
- Apple provider reference at
  `afb1ac6fd63aeb4660f39b21bde4a3f52cdee9fa`

The Apple provider repository is semantic reference material only. In
particular, code that obtains a packet-flow file descriptor through KVC is not
used.

## Development

Every change follows the standards in
[`docs/engineering-standards.md`](./docs/engineering-standards.md): fail-fast
error handling, no silent fallbacks, zero warnings, and CI-parity verification
before delivery.

On macOS 15+ Apple Silicon:

```sh
./scripts/assert_apple_silicon.sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets

cd apps/cfw-tauri-shell
npm ci
npm run build

cd ../../native/macos
swift test -Xswiftc -warnings-as-errors
```

The UI build writes only generated files under
`apps/cfw-tauri-shell/ui/dist`; generated JavaScript is not maintained as
source.

## Source-built libbox

Tool acquisition and module-cache preparation are explicit networked steps.
The actual libbox build is offline and accepts only the materialized source
whose upstream commit, dependency-security patch, public packet-flow adapter
patch, and combined source diff all match their pins:

```sh
./scripts/bootstrap_release_toolchain.sh

SING_BOX_SOURCE=/absolute/path/to/clean-upstream-sing-box \
LIBBOX_PATCHED_SOURCE_OUTPUT=/absolute/path/to/patched-sing-box \
  ./scripts/materialize_libbox_source.sh

SING_BOX_SOURCE=/absolute/path/to/patched-sing-box \
  ./scripts/prepare_libbox_modules.sh

SING_BOX_SOURCE=/absolute/path/to/patched-sing-box \
  ./scripts/scan_libbox_vulnerabilities.sh

SING_BOX_SOURCE=/absolute/path/to/patched-sing-box \
  ./scripts/build_libbox.sh
```

The build refuses a different commit, any diff beyond the exact three-patch
series, a wrong Go/gomobile toolchain, changed module files, existing output,
or missing offline module cache. It records a path-independent SHA-256 tree
manifest for the produced XCFramework. See
[`docs/supply-chain.md`](./docs/supply-chain.md).

## License

Copyright (C) 2026 bill.

This project is licensed under the GNU General Public License, version 3 or (at
your option) any later version. See [`LICENSE`](./LICENSE). Distributions must
provide the complete corresponding source and the required license and
modification notices. Reference-only third-party artifacts retain their own
terms and are identified beside the material; see
[`reverse/cfw-0.20.39-arm64/THIRD_PARTY_NOTICES.md`][reference-notice].

[reference-notice]: ./reverse/cfw-0.20.39-arm64/THIRD_PARTY_NOTICES.md
