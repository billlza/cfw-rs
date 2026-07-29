# macOS release gate

This project releases only an arm64 application for macOS 15 or newer. A green
Rust, JavaScript, or Swift unit-test lane is necessary but does not establish a
releasable Network Extension product.

## Current source composition and release boundary

The v0.4.0 Release source graph now composes the real native path rather than
the earlier missing-link placeholders:

- the Rust application uses `NativeFrameworkBridge` and the fixed
  `CFWNativeBridge.framework` ABI;
- the Host registers the root-context Global Authority with `SMAppService`,
  registers the user `CFWProxyAgent`, and drives `SystemExtensions` plus
  `NETunnelProviderManager` through public APIs;
- ProxyAgent and `com.bill.clashformac.packet-tunnel.systemextension` both
  construct the pinned,
  source-built libbox runtime;
- the Packet Tunnel moves packets through bounded public
  `NEPacketTunnelFlow` reads/writes and a connected `AF_UNIX/SOCK_DGRAM` pump;
  and
- one Global Authority process owns the durable machine-wide lease, recovery
  journal, liveness supervision, and three role-scoped XPC services for Host,
  ProxyAgent, and Provider. Each direction applies an exact public code-signing
  requirement before exporting its typed protocol.

The libbox input is upstream sing-box `v1.13.14` at commit
`25a600db24f7680ad9806ce5427bd0ab8afe1114` plus three digest-pinned repository
patches: security dependency updates, the public raw-packet adapter, and bounded
DNS failover. The exact combined diff and patched `go.mod`/`go.sum` digests are
release inputs in `scripts/dependency_pins.env` and
`native/macos/Dependencies.lock.json`. The previous helper, mihomo, clash-rs,
downloaded core, and private packet-flow file-descriptor access are not
fallbacks.

These are source-composition and deterministic-test claims. An unsigned
candidate proves that the four native products and outer application can be
built and structurally bundled; it cannot prove signing identity, XPC
admission, System Extension approval, Network Extension traffic, notarization,
Gatekeeper, or publication. Do not promote or publish v0.4.0 until the exact
unchanged candidate also passes all signed-installed, physical-machine,
notarization, final-candidate, and publication gates below.

The shipped composition must not construct any `FailClosed*Owner*` Authority or
effective-state placeholder, default `signedChannelProven` to false, permanently
validate `.availabilityUnproven`, or reach `NSXPCConnection.auditToken` through
a private selector or `unsafeBitCast`. Test fixtures may model those failures;
production composition may not ship them.

The current closed application profile schema supports typed `direct`,
`block`, Shadowsocks, VMess, VLESS/Reality, Trojan, and Hysteria2 outbounds; it
must not be marketed as full sing-box configuration support. Profile JSON may
contain immutable canonical `credential_ref` values but never secret bytes.
The source implements missing-only shared-Keychain provisioning, presence
checks, authenticated in-memory native slot injection, and revision-bound
orphan cleanup. Release remains blocked until those paths pass under installed
signed Host/ProxyAgent/System Extension identities on physical machines.
Legacy proxy or DNS cleanup requiring manual review is a visible migration
gate, not a condition a release build may silently clear.

Each durable Authority journal generation is bounded to 4,096 records and
32 MiB. Before a prepare would consume the seven-record lifecycle finish
reserve, the store commits a hash-chained checkpoint into the next anchored
generation and retains only the active and previous generations. Recovery
fails closed on rollback, malformed generation state, an insecure cleanup
target, or cleanup failure. Deterministic fault-injection tests cover every
checkpoint commit and obsolete-generation cleanup crash boundary; those source
and unit-test claims do not replace the physical-machine longevity and soak
gates below.

Launching the app must never stop or mutate the legacy VPN, System Proxy,
routes, or DNS. A release candidate must prove that replacement profiles can be
staged under `sing-box-profiles-v1` while historical `profiles` state remains
untouched, and that the one-way tombstone is unreachable until an explicit
user confirmation and server-side native/profile preflight both succeed.

The release operator must have:

- a Developer ID identity with the exact product Team ID;
- explicit Network Extension and System Extension provisioning for the app and
  Packet Tunnel bundle identifiers;
- the matching App Group, host Keychain group, and ProxyAgent Keychain group;
- no Data Protection Keychain access-group entitlement on the Packet Tunnel
  system extension;
- the exact host-only Keychain group for Keychain-authoritative generation
  lineage, isolated from ProxyAgent and every system-extension store;
- a notarytool Keychain profile;
- the Tauri updater signing key outside the repository;
- clean macOS 15 and current macOS Apple Silicon test machines.

`verify_release_environment.sh` rejects ignored `.key`/`.pem` material under
the repository workspace. Git ignore rules are not a key-management boundary:
the active updater key must live in an access-controlled external secret store
or hardware-backed workflow. If a workspace copy may have escaped through a
backup or shared archive, rotate the key and publish an explicit updater trust
migration before release.

## 1. Prepare and seal networked release inputs

```sh
./scripts/bootstrap_release_toolchain.sh
./scripts/install_pinned_tauri_cli.sh
./scripts/prepare_ui_dependencies.sh
SING_BOX_SOURCE=/absolute/path/to/clean-upstream-sing-box \
LIBBOX_PATCHED_SOURCE_OUTPUT=/absolute/path/to/patched-sing-box \
  ./scripts/materialize_libbox_source.sh
SING_BOX_SOURCE=/absolute/path/to/patched-sing-box \
  ./scripts/prepare_libbox_modules.sh
```

Review [`docs/supply-chain.md`](./docs/supply-chain.md). Verify that the release
commit, submodule/reference state, version, changelog, and complete
corresponding-source candidate are immutable and have recorded SHA-256 hashes.

## 2. Verify the sealed inputs and build libbox offline

Preparation is explicit and networked; the release build is offline:

```sh
./scripts/verify_release_environment.sh
./scripts/verify_build_boundaries.sh
cargo metadata --locked --format-version 1 >/dev/null
SING_BOX_SOURCE=/absolute/path/to/patched-sing-box \
  ./scripts/scan_libbox_vulnerabilities.sh
SING_BOX_SOURCE=/absolute/path/to/patched-sing-box \
  ./scripts/build_libbox.sh
```

The Tauri installer verifies the official 2.11.4 crate and its published lock,
applies the digest-pinned `spin` 0.9.9 lock update, verifies the resulting lock,
and installs only from that local source with `--locked` using isolated Cargo
home and target directories. The sealed payload contains only its thin arm64
binary and clean patched crate source, lock, and licenses under
`target/toolchains/tauri-cli-2.11.4`. Release scripts invoke that absolute
binary; an ambient Cargo home cannot substitute it. Go, Node.js, XcodeGen,
Tauri, the Go release tools, and the prepared Go module cache must each have a verified
`sha256-tree-v2` manifest before use. A directory without its matching manifest,
or any content/type/mode/symlink/metadata drift, requires an explicit clean
bootstrap and is never accepted from `--version` output alone.
The XcodeGen source build also verifies and applies the pinned installed-resource
patch, proves `SettingPresets` loading by generating a probe project, strips
debug paths, and rejects a binary containing its temporary bootstrap root.

Archive the emitted XCFramework tree manifest, Go module verification output,
upstream identity, all three downstream patches, the combined source-diff digest,
patched module digests, vulnerability scan, build tags, and tool identities.
Reject any unproven binary.

## 3. Quality gates

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo deny --locked --target aarch64-apple-darwin check

pinned_node_bin="$PWD/target/toolchains/node-24.18.0/bin"
PATH="$pinned_node_bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  "$pinned_node_bin/npm" --prefix apps/cfw-tauri-shell test
./scripts/build_ui_with_pinned_node.sh
PATH="$pinned_node_bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  "$pinned_node_bin/npm" --prefix apps/cfw-tauri-shell audit --audit-level=high

cd native/macos
swift test -Xswiftc -warnings-as-errors
xcodebuild test \
  -project CFWNative.xcodeproj \
  -scheme CFWNativeTests \
  -destination 'platform=macOS,arch=arm64' \
  CODE_SIGNING_ALLOWED=NO
xcodebuild analyze \
  -project CFWNative.xcodeproj \
  -scheme CFWPacketTunnelExtension \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO
xcodebuild analyze \
  -project CFWNative.xcodeproj \
  -scheme CFWProxyAgent \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO
```

Every command must complete without project-owned errors or warnings. Upstream
advisories without a safe compatible release remain release blockers unless the
dependency is proven unreachable in the shipped target and the project owner
accepts the exact documented boundary; advisory IDs are never silently ignored.
`cargo deny` is the blocking RustSec/license/source/bans gate because it resolves
the actual `aarch64-apple-darwin` graph. `cargo-audit` is not used as a release
gate: its target flags filter vulnerabilities but not warning advisories, so the
unified Tauri lockfile reports twelve Linux GTK warnings that do not resolve in
the shipped macOS graph. No advisory is ignored or suppressed; a dependency that
does resolve in the target graph remains blocking.

## 4. Native data-plane evidence

Run the signed app on clean physical Apple Silicon machines. Capture unique
per-test tokens and packet evidence for TCPv4, TCPv6, UDP/QUIC, DNS A/AAAA, LAN
bypass, included routes, and excluded routes. A connected VPN status or an
existing `utun` interface is not data-plane evidence.

Required network conditions:

- 100 ms latency, 1% loss, 10 Mbps;
- 300 ms latency, 5% loss, 1 Mbps;
- 30-second network outage and recovery.

Required product cases include approval, denial, pending approval, upgrade and
replacement, restart-required, downgrade refusal, multiple users, sleep/wake,
fast-user switching, Host/Global Authority/Provider/ProxyAgent crashes,
concurrent mode requests, cancellation, reboot recovery, and uninstall cleanup.
The run must prove the role-scoped XPC identity policy with the installed
Developer ID identities and prove that revocation or connection loss reaches a
truthful Off or Quarantined terminal state. Unit tests of those state machines
do not replace the installed-process run.

System Proxy apply/restore uses
`SCPreferencesCreateWithAuthorization` from the non-root ProxyAgent. The signed
physical matrix must include recovery after the Authorization Services right
has expired and while no interactive prompt can be serviced. If unattended
restore cannot be proven with that public boundary, release requires a narrow,
code-identity-checked privileged SystemConfiguration service; it must never
become a core launcher or a general command/file interface.

The performance and resource limits are those in
[`docs/performance-stability-targets.md`](./docs/performance-stability-targets.md).
No probe may be skipped or converted to success after a failure.

## 5. Bundle and sign from the inside out

The fixed order is:

1. source-built libbox framework;
2. ProxyAgent;
3. Packet Tunnel `.systemextension`;
4. Tauri app skeleton and embedded native products;
5. outer `.app`;
6. distribution image and updater archive.

The System Extension belongs under
`Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension`;
the wrapper basename must remain the exact Packet Tunnel bundle identifier.
Its `CFBundleExecutable` is `CFWPacketTunnel`. Verify each nested code object
before signing its parent.

The pinned Tauri CLI only assembles the Host skeleton. Candidate builds reject
every Tauri signing identity or certificate input, reject platform-specific
configuration overlays, and then prove that the outer app has only the
linker-generated ad-hoc CodeDirectory with no resource seal, Team ID,
certificate authority, timestamp, or entitlements. The signed lane repeats
that proof after staging before it installs the Host profile and applies the
reviewed Developer ID signature. This avoids Tauri's `--no-sign` diagnostic
without allowing it to select or apply a signature.

At every layer record:

```sh
file PATH
lipo -archs PATH
codesign --verify --strict --verbose=4 PATH
codesign -d --verbose=4 PATH
codesign -d --entitlements - --xml PATH
```

The evidence must prove arm64-only slices, Team ID, bundle identifiers,
entitlements, matching provisioning, hardened runtime, secure timestamp, and
macOS 15 deployment target. Any mismatch blocks the outer signature.

## 6. Notarize, staple, and package

Submit the signed app, wait for an accepted result, staple the ticket, and
verify both stapler and Gatekeeper before creating the DMG. Then run the same
notarization and staple validation for the DMG.

An accepted submission summary alone is insufficient. The signed-candidate
builder retrieves and preserves `notarization-log.json`, binds its job ID and
archive SHA-256 to the submitted ZIP, and rejects every issue or warning before
stapling. Gatekeeper assessment is valid only while `spctl --status` reports
exactly `assessments enabled`; `override=security disabled` is a release
failure even if the assessment line says `accepted`. The captured
`gatekeeper.json` preserves the raw status, assessment, and codesign output plus
their digests, notarized source, Developer ID authority, and origin.
This intentionally advances the outer final-candidate binding to schema v2;
pre-existing v1 bindings lack the effective Gatekeeper-state proof and must be
regenerated rather than migrated or accepted through a compatibility wrapper.

The signed-candidate builder also requires a clean repository and records the
real Git `HEAD` together with the complete release-source digest in every native
manifest and final app/archive manifest. It rechecks both identities after the
application build and again before sealing the final artifacts. The final
candidate binder rejects a merely well-formed 40-hex value unless it equals the
repository's current `HEAD`; no caller-supplied commit can stand in for source
identity.

`scripts/make_dmg.sh` and `scripts/make_updater_manifest.sh` are post-signing
steps. They must not modify nested code or rescue a failed signature.
Both commands first run `scripts/verify_release_app.sh`. That gate requires the
fixed Team ID `YKUPL7Z869`, host `com.bill.clashformac`, Packet Tunnel
`com.bill.clashformac.packet-tunnel`, ProxyAgent
`com.bill.clashformac.proxy-agent`, App Group
`YKUPL7Z869.group.com.bill.clashformac`,
arm64-only macOS 15 Mach-O slices, matching unexpired Developer ID provisioning
profiles and certificates, hardened runtime, secure timestamps, accepted
notarization staple, and Gatekeeper approval. It permits only the source-bound
one-way helper tombstone and rejects every former core/helper layout.

Both packaging commands call `release_publication_gate.sh`. The gate now verifies
the sealed publication evidence but remains fail closed until that evidence has
been prepared, legally reviewed, and finalized for the exact signed app. It has
no success override and accepts only:

- `target/candidates/0.4.0/signed/Clash for Mac.app` as the signed binary root;
- `target/candidates/0.4.0/release/publication` as the final evidence root.

It never scans or accepts `target/release`, which retains historical 0.3.5
signed artifacts containing the old core/helper layout.

Run the publication phases after the exact app has been signed, notarized, and
stapled:

```bash
scripts/prepare_publication_evidence.py review-template \
  --libbox-source target/sources/sing-box-v1.13.14-patched

# Resolve every item in component-review.json and every source blocker, then:
scripts/prepare_publication_evidence.py prepare \
  --libbox-source target/sources/sing-box-v1.13.14-patched \
  --reviewed-components target/candidates/0.4.0/review/component-review.json

python3 scripts/publication_evidence.py draft \
  --prepared target/candidates/0.4.0/release/publication-prepared \
  --app "target/candidates/0.4.0/signed/Clash for Mac.app" \
  --output target/candidates/0.4.0/release/machine-closure.draft.json

# A human legal reviewer must approve the exact printed closure digest and
# component set in target/candidates/0.4.0/review/legal-review.json.
python3 scripts/publication_evidence.py finalize \
  --prepared target/candidates/0.4.0/release/publication-prepared \
  --app "target/candidates/0.4.0/signed/Clash for Mac.app" \
  --review target/candidates/0.4.0/review/legal-review.json \
  --output target/candidates/0.4.0/release/publication

scripts/release_publication_gate.sh \
  "$PWD/target/candidates/0.4.0/signed/Clash for Mac.app"
```

Do not copy component or blocker counts from an older review into a release
claim. `component-review.json`, `publication-blockers.json`, the SBOM, and every
corresponding-source root must be regenerated after any lock, source, patch,
tag, toolchain, or bundle change. Every package attribution and every reported
license/source blocker requires human legal disposition for the exact
candidate. A template is never accepted as release evidence.

The updater command accepts only a strict SemVer equal to the signed app
version. It emits only the fixed `darwin-aarch64`/`darwin-arm64` targets under
the repository's HTTPS GitHub Releases origin and immediately verifies the
new signature with the public key embedded in `tauri.conf.json` before writing
`latest.json`. Both the packaging verifier and runtime require the authenticated
minisign trusted comment to name that exact versioned archive; an older valid
signature cannot be replayed under a newer manifest version or GitHub release
path. Downloads are streamed through the fixed 192 MiB admission limit and are
installed only after signature and signed-filename verification succeeds.
The synchronous macOS install commit is additionally admitted only when the
running executable is the exact non-symlink
`/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac`, the bundle and
executable have trusted ownership and non-writable group/other metadata, and
the updater's pinned temporary root is a private current-user directory on the
same volume as the installed app. The project-owned updater accepts at most
64 KiB of strict metadata and 192 MiB of signed compressed data. Before commit,
it independently enforces 50,000 entries, 512 MiB per regular file, 1 GiB total
regular-file payload, canonical bundle layout, explicit directories, unique and
non-conflicting paths, relative in-bundle symlinks, and safe entry types and
permissions. Extraction uses directory descriptors with `openat`/`mkdirat` and
`O_NOFOLLOW`; it never delegates path handling to the tar library. It then
verifies bundle version, code signature, and Gatekeeper assessment, proves the
network engine is Off while holding an exclusive maintenance barrier, and uses
an atomic same-volume swap. The former Tauri updater runtime and its privileged
AppleScript fallback are not linked.

## 7. GPL publication set

Publish these artifacts together:

- signed/notarized/stapled application distribution;
- updater artifact and signature;
- complete corresponding source for the exact binary;
- GPLv3-or-later license and modification notice;
- Rust, npm, Swift, Go, and native SBOMs merged into the release SBOM;
- third-party license texts and notices for every shipped component, plus a
  review proving that reference-only `reverse/` artifacts are absent from all
  binary/update payloads;
- source, libbox XCFramework, nested native binary, app, DMG, updater, and SBOM
  SHA-256 manifest;
- reproducible build instructions and the exact dependency pin file.

Verify the public URLs, sizes, hashes, signatures, and source archive after
publication. Local artifacts do not prove successful publication.
