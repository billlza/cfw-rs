# macOS release gate

This project releases only an arm64 application for macOS 15 or newer. A green
Rust, JavaScript, or Swift unit-test lane is necessary but does not establish a
releasable Network Extension product.

## Release-blocking boundary

Do not produce or publish a release while either native target uses
`MissingLibboxEngineFactory`, while the Rust-to-Swift Host Bridge is absent, or
while the public packet-pump/libbox contract has not passed correctness and
performance tests. The Packet Tunnel must also replace
`systemExtensionStateTransportNotLinked` with authenticated global-context XPC,
provider-owned replay state, and a cross-user/cross-mode global lease. A user
App Group file or Data Protection Keychain item cannot cross the root system
extension boundary. The previous helper, mihomo, clash-rs, downloaded core, and
private packet-flow file-descriptor access are not fallbacks.

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

## 1. Verify source and toolchain

```sh
./scripts/verify_release_environment.sh
./scripts/verify_build_boundaries.sh
cargo metadata --locked --format-version 1 >/dev/null
```

Review [`docs/supply-chain.md`](./docs/supply-chain.md). Verify that the release
commit, submodule/reference state, version, changelog, and complete
corresponding-source candidate are immutable and have recorded SHA-256 hashes.

## 2. Build libbox from source

Preparation is explicit and networked; the release build is offline:

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

Archive the emitted XCFramework tree manifest, Go module verification output,
upstream identity, both downstream patches, the combined source-diff digest,
patched module digests, vulnerability scan, build tags, and tool identities.
Reject any unproven binary.

## 3. Quality gates

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo deny --locked --target aarch64-apple-darwin check

target/toolchains/node-24.18.0/bin/npm --prefix apps/cfw-tauri-shell ci
./scripts/build_ui_with_pinned_node.sh
target/toolchains/node-24.18.0/bin/npm --prefix apps/cfw-tauri-shell audit --audit-level=high

cd ../../native/macos
swift test
xcodebuild test \
  -project CFWNative.xcodeproj \
  -scheme CFWNativeTests \
  -destination 'platform=macOS,arch=arm64' \
  CODE_SIGNING_ALLOWED=NO
xcodebuild analyze \
  -project CFWNative.xcodeproj \
  -scheme CFWPacketTunnel \
  -destination 'platform=macOS,arch=arm64'
xcodebuild analyze \
  -project CFWNative.xcodeproj \
  -scheme CFWProxyAgent \
  -destination 'platform=macOS,arch=arm64'
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
provider crash, ProxyAgent crash, concurrent mode requests, cancellation, and
uninstall cleanup.

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
`Contents/Library/SystemExtensions`. Verify each nested code object before
signing its parent. At every layer record:

```sh
file PATH
lipo -archs PATH
codesign --verify --strict --verbose=4 PATH
codesign -d --verbose=4 PATH
codesign -d --entitlements :- PATH
```

The evidence must prove arm64-only slices, Team ID, bundle identifiers,
entitlements, matching provisioning, hardened runtime, secure timestamp, and
macOS 15 deployment target. Any mismatch blocks the outer signature.

## 6. Notarize, staple, and package

Submit the signed app, wait for an accepted result, staple the ticket, and
verify both stapler and Gatekeeper before creating the DMG. Then run the same
notarization and staple validation for the DMG.

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

The current 371-component closure has 27 explicit license-review blockers and
8 missing corresponding-source roots. All 371 package copyright attributions
also require human confirmation; standard license boilerplate is not accepted
as package attribution. The exact IDs and reasons are in
`target/candidates/0.4.0/review/publication-blockers.json`; those ignored review
outputs must be regenerated after any lock, source, tag, toolchain, or bundle
change. A template is never accepted as release evidence.

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
