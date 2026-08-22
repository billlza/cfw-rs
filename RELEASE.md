# macOS release gate

This project releases only an arm64 application for macOS 15 or newer. A green
Rust, JavaScript, or Swift unit-test lane is necessary but does not establish a
releasable Network Extension product.

Android and iOS are not release targets. Physical interoperability may use an
iOS device as a test peer, but its harness, device identity, transport capture,
and receipts must be independently source-bound; an Android peer record cannot
be renamed or reused as iOS evidence.
The repository's test-only iOS transport peer remains outside the product and
release bundle. The iPhone Packet-LAN mode now replaces the Android peer as the
active `lan-bypass` evidence source, but no prior pilot or Android receipt is
reusable: every candidate requires a fresh dynamic ready address, three joint
Mac/iPhone connection bindings, pcap/Host evidence, and exact cleanup.

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

The libbox input is upstream sing-box `v1.13.15` at commit
`3708fa18766cda1f11b77f6ed9c7bd61688f17df` plus four digest-pinned repository
patches: security dependency updates, the public raw-packet adapter, bounded
DNS failover, and structured loopback endpoint-conflict reporting. The exact
combined diff and patched `go.mod`/`go.sum` digests are
release inputs in `scripts/dependency_pins.env` and
`native/macos/Dependencies.lock.json`. The previous helper, mihomo, clash-rs,
downloaded core, and private packet-flow file-descriptor access are not
fallbacks.

The security patch pins `golang.org/x/mod v0.40.0` and its exact tested `x/*`
closure to remove `GO-2026-6179` and `GO-2026-6180`. The release vulnerability
scan must report zero affected symbols and zero affected imported packages
without an ignore. `GO-2026-5932` may remain only as the documented module-level
`x/crypto/openpgp` report: the package has no fixed version and must remain
absent from the libbox import graph.

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
`block`, Shadowsocks, VMess, VLESS/Reality, Trojan, Hysteria2, AnyTLS, and TUIC
v5 outbounds; it must not be marketed as full sing-box configuration support.
Profile JSON may contain immutable canonical credential references, including
separate TUIC UUID and password references, but never secret bytes.
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
- exact Developer ID profiles for the Host, Packet Tunnel, and ProxyAgent
  bundle identifiers, including the Host/System Extension and Packet Tunnel
  Network Extension authorizations;
- the matching App Group, host Keychain group, and ProxyAgent Keychain group;
- no Data Protection Keychain access-group entitlement on the Packet Tunnel
  system extension;
- the exact host-only Keychain group for Keychain-authoritative generation
  lineage, isolated from ProxyAgent and every system-extension store;
- the validated `clashformac-notary` notarytool Keychain profile;
- the encrypted Tauri updater signing key outside the repository and its
  non-synchronizing Keychain-held password;
- one physical Apple Silicon test Mac that can boot separate clean macOS 15
  and current-macOS environments.

`verify_release_environment.sh` rejects `.key`, `.pem`, or `.p8` material under
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
home and target directories. It normalizes only Cargo's three exact root-level
runtime tracking/lock files in the private offline cache copy, then proves the
complete remaining registry tree is byte-identical before and after compilation.
The normalization helper digest and policy are bound into the final toolchain
manifest, and any fetch or install warning blocks the bootstrap. The sealed
payload contains only its thin arm64 binary and clean patched crate source, lock, and licenses under
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
upstream identity, all four downstream patches, the combined source-diff digest,
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

Run the signed app on one controlled physical Apple Silicon Mac, sequentially
booted into the two source-pinned clean OS environments. Both runs must bind
the same machine identity while retaining distinct run IDs, nonces, receipts,
and raw archives. Capture unique per-test tokens and packet evidence for TCPv4,
TCPv6, UDP/QUIC, DNS A/AAAA, LAN bypass, included routes, and excluded routes.
A connected VPN status or an existing `utun` interface is not data-plane
evidence.

The receive-only Packet peer under `tools/packet-evidence-endpoint/` is bound
to the repository-pinned Go toolchain and reproducible Linux/amd64 digest
`c63c202b22823197ad12cb2d5f484c95be25904260ed266083dcca6fc766db6c`.
Its sole Debian installation transaction is the pinned
`install-endpoint.sh` digest
`14b45b1705f762057ac38d836f2ac5c7d3721e72ec0ec45b72505b354f0d05c8`;
the systemd unit, fixed GCE resolver, and exact capture sudoers bytes have
digests `7d485a9fe9081ebf019fcc8abc1d596358a64326e2490749d9903197262e3996`,
`b290cc794e7f0faac9ebbd63f83aad67d23086b48206295d5d6a2767721c1e62`,
and `a91c2bc91a294622d44f14e2cad653b9703fcf70afa42bf91e0248ef240c3411`.
Do not commit its generated target binary. The reviewed endpoint and
known-hosts policies now bind the three concrete GCE instances, external
addresses, image and service identities, separate primary/secondary DNS SSH
host keys, the dedicated non-admin capture service account, instance-scoped OS
Login/IAP port-22 grants, and strict streamed `tcpdump -c 6 -w -` command. DNS
is UDP-only: the product trigger is `getaddrinfo`, while the independent remote
pcap must contain each exact query and authoritative response. A local FakeIP
answer is not accepted as the endpoint answer.

The IAP grant lives on each IAP TCP tunnel instance resource policy, not on the
Compute instance or project IAM policy. Its only admitted binding is the fixed
capture service account with `roles/iap.tunnelResourceAccessor`, title
`packet-capture-ssh-only`, and condition `destination.port == 22`.

This provisioning is not itself physical candidate evidence. The active
`lan-bypass` producer now admits one source-hash-selected physical iPhone,
revalidates the signed thin-arm64 test app and provisioning authority, obtains
the endpoint only from a fresh `en0` ready receipt, proves connected/prepared
device details after any dormant wireless inventory observation, rechecks the
unlocked state immediately before both launches, and reconciles three ordered
TCP/EOF server observations with the Mac sender tuples before exact PID
termination and owned-app uninstall. An adapter-level physical pilot passed,
but no fresh complete 13-case candidate Packet run has yet been collected.
The retained Android peer is inactive legacy test infrastructure. A
syntactically legal pcap, live endpoint, prior pilot, or manual capture cannot
substitute for the frozen product-state, route/interface, capture, send,
server, restore, and cleanup receipts.

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

The lifecycle lane is schema v4 with an exact 72-subject receipt contract. Its
pre-nonce phase retains 32 distinct `lifecycle-observation` documents plus
eight special trace/packet/pixel artifacts, all proof-free, and freezes those
40 subjects at `RAW_COMPLETED`. Only after nonce receipt may the deterministic
materializer emit the 32 `lifecycle-event` v3 artifacts, each referencing one
frozen observation. The five identity observations are included in the 32;
they are not five additional subjects. Report v3, event v2, a pre-nonce
`proof`/`run_nonce`, missing or relabelled observations, duplicate paths or
digests, and a 272nd receipt descriptor all fail closed. An interrupted
post-nonce materialization may reuse only byte-identical existing event files;
it never replaces them or regenerates timestamps.

The adversarial lane is schema v3: one baseline plus 32 source-pinned cases and
exactly 138 receipt-bound raw subjects. Each case retains a proof-free
precondition observation, independent client and installed-Authority signature
observations, the actual server/boundary decision and raw request digest, and a
post-nonce transcript derived only from the frozen RAW_COMPLETED manifest. The
six secret cases additionally require complete one-way-canary coverage
manifests; plaintext canaries are never evidence. Privileged, journal, FUS, and
secret cases must prove reset to their isolated pre-state, and the collector
must stop at the first cleanup failure. The fixed controller currently closes
only the baseline and Foundation signing-requirement variants; the remaining
root-owned physical scenarios remain release blockers and must not be
represented by declared expected output or a debug XPC method. The isolated
designated-requirement variant must be signed by a valid same-Team Apple
identity that preserves the exact Host identifier and App Group while failing
only the listener's Developer-ID certificate/OID clauses. The SDK does not
expose an `NSXPCConnection.auditToken` member; Foundation's documented
pre-delegate listener requirement remains the single peer-identity gate, and
private selector or `unsafeBitCast` substitutes are forbidden.

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
their digests, notarized source, Developer ID authority, and origin. It is
private release-operations evidence because its exact target and command fields
contain local absolute paths; it is never an upload asset. The distribution
transaction instead derives a canonical path-free public projection only after
revalidating that private document against the original assessed target and the
final DMG bytes. The projection binds the exact private-document SHA-256,
assessment policy/result, target digest, signing identity, and capture time.
This intentionally advances the outer final-candidate binding to schema v3;
pre-existing v1/v2 bindings lack either the effective Gatekeeper-state proof or
the PS256 physical aggregate to physical-candidate artifact-manifest
cross-binding and must be regenerated rather than migrated or accepted through
a compatibility wrapper.

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

DMG notarization is a durable single-submission transaction. The DMG is moved
into a private attempt before `/usr/bin/xcrun notarytool submit --no-wait` is
called, made read-only, and retained as the immutable pre-staple source. The
exact filename, pre-staple size/SHA-256, source identity, bounded submit window,
submission-ID observation, and hash-chained events survive a crash. A normal
rerun is refused once an attempt exists. Resume only with the same Apple ID:

```bash
NOTARY_PROFILE=clashformac-notary \
  scripts/make_dmg.sh --recover-submission-id UUID
```

If the submit reply was lost before its ID could be persisted, recovery
requires the operator-supplied ID and proves a unique `notarytool info` plus
complete `history` match inside the durable submit window. Ambiguity blocks;
the script never submits another DMG. Recovery then retrieves and validates the
log, creates a private copy of the immutable source, staples and validates that
copy, captures Gatekeeper evidence, runs `hdiutil verify` and
`codesign --verify`, and continues without rebuilding the DMG. Recovery
discards every unpublished staple-pending or final-set copy and recreates it
from the immutable submitted bytes, so a valid but unrelated stapled DMG cannot
be substituted after a crash. Final publication fsyncs the sealed destination
tree and both rename parents; a `publication_deferred` attempt is recoverable
only by closing that durability boundary and re-verifying the exact final set.

Run the publication phases after the exact app has been signed, notarized, and
stapled:

```bash
scripts/prepare_publication_evidence.py review-template \
  --libbox-source target/sources/sing-box-v1.13.15-patched

# Resolve every item in component-review.json and every source blocker, then:
scripts/prepare_publication_evidence.py prepare \
  --libbox-source target/sources/sing-box-v1.13.15-patched \
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

### Fixed 40021 to 40022 physical-candidate evidence sequence

The production evidence composer has no fixture, path, output, build-number, or
success-override option. Run this sequence exactly once from one clean release
commit. Build identities through `40020` have already been allocated to older
source closures or validation attempts. Build `40020` terminated at its
fail-closed host-compatibility gate before Apple submission and remains an
immutable retired attempt. Those candidates and their evidence must not be
renamed, relabelled, or reused:

1. build, notarize, install, and exercise validation build `40021`; preserve its
   fixed CI/toolchain, app-manifest, notarization, and runtime-recovery records;
2. have a human reviewer approve those exact bytes in
   `target/candidates/0.4.0/review/validated-candidate.json`;
3. build, sign inside-out, notarize, staple, and Gatekeeper-verify final build
   `40022` from the same clean source identity;
4. freeze the signed/notarized runtime candidate before collection:

   ```bash
   python3 -B scripts/production_release_evidence.py \
     prepare-physical-candidate-manifest
   ```

   This exclusively creates
   `target/candidates/0.4.0/release/final-candidate/physical-candidate-artifact-hash-manifest.json`
   and the exact collector projection
   `target/candidates/0.4.0/release/final-candidate/physical-collector-candidate.json`.
   It reopens the publish-ready notarization receipt and journal lineage and
   binds the post-staple app, app manifest, libbox, notarization archive/result/
   log, Gatekeeper evidence, publication closure, SBOMs, receipt, intent, and
   event tree. It refuses to replace an existing file; any drift requires a new
   build and clean evidence root, never an in-place rewrite;
5. run the source-pinned production collector for both required clean OS
   environments (`macos15` and `current-macos`) on the same physical Mac,
   following
   [`docs/physical-evidence-v5.md`](./docs/physical-evidence-v5.md). Both PS256
   run receipts and the aggregate must bind the exact manifest digest from step
   4. Retain all raw private bytes and place only the strict aggregate descriptor
   at
   `target/candidates/0.4.0/release/final-candidate/physical-evidence.json`;
   the current policy requires a 3-hour operator-observed interval with no
   reported crash on each pinned OS. This duration and timestamp/crash-list
   evidence model are approved only for the small internal distribution; they
   are neither a remote liveness attestation nor a public-GA stability claim;
   before requesting either nonce, redeploy and rebind the lifecycle-v4 Go
   collector source/image/trust policy and install the reviewed root-owned
   lifecycle probe. The previously deployed collector digest and revisions do
   not authorize this changed 72-subject contract; local tests or a root-owned
   binary without the reviewed source/image binding are not production
   evidence;
6. after both OS-run archives are complete, seal the runtime evidence:

   ```bash
   python3 -B scripts/production_release_evidence.py seal
   ```

   The composer reopens every input, rehashes the final `.app` after all other
   evidence, validates the fixed 99 capability-owned report bindings, and
   exclusively publishes the private documents under
   `target/candidates/0.4.0/release/sealed-manifest/`. A pre-existing output,
   absent raw archive, unconfigured collector trust policy, receipt ambiguity,
   hash drift, stale timestamp, missing capability, or failed gate blocks the
   seal.

This physical-candidate manifest and sealed runtime evidence intentionally do
not claim to contain a DMG, updater signature, or remote release asset. Only
after step 6 may the post-signing DMG/updater packaging transactions run. Their
later distribution artifact-set seal binds the final DMG, updater archive and
signature, public projections, upload bundle, and remote-download verification;
neither layer may be renamed or treated as the other.

Do not copy component or blocker counts from an older review into a release
claim. `component-review.json`, `publication-blockers.json`, the SBOM, and every
corresponding-source root must be regenerated after any lock, source, patch,
tag, toolchain, or bundle change. Every package attribution and every reported
license/source blocker requires human legal disposition for the exact
candidate. A template is never accepted as release evidence.

The updater command accepts only a strict SemVer equal to the signed app
version. It emits only the fixed `darwin-aarch64`/`darwin-arm64` targets under
the repository's HTTPS GitHub Releases origin. The artifact-set sealer itself
builds `cfw-release-verifier` offline with the pinned Rust toolchain and invokes
that exact executable against the staged archive and signature; it does not
accept a caller-produced `result=verified` receipt. The seal binds the verifier
source inputs, Cargo and rustc identities and versions, controlled build and
verification commands, and executable SHA-256. The build rejects every
repository, ancestor, or Cargo-home config, clears wrapper and flag injection
variables, uses a private Cargo home and isolated workspace, and reconstructs
its vendor tree only from crate archives whose SHA-256 matches the exact
`Cargo.lock` dependency closure. The declared rustup component file surface is
independently pinned in both `dependency_pins.env` and
`pinned_build_inputs.json`. Every updater, distribution, and upload
verification repeats that isolated build and signature verification, reopens
the archive, signature, source, dependency, and toolchain inputs, and requires
the fresh receipt and build binding to equal the stored evidence. The
packaging verifier requires the authenticated minisign trusted comment to name
that exact versioned archive; an older valid signature cannot be replayed under
a newer manifest version or GitHub release path.

The runtime performs only a bounded metadata check against the canonical
official GitHub release identity and then opens the official DMG release page
for a user-controlled update. It does not download, extract, or atomically swap
the installed app and must not report a browser handoff as installation. After
an external replacement, the `SMAppService` daemon requires an explicit,
verified re-registration transaction before native services resume. That
transaction is not implemented in 0.4.0, so in-process replacement is
intentionally absent and no metadata/browser handoff is reported as a completed
installation. The former Tauri updater runtime, in-process archive installer,
and privileged AppleScript fallback are not linked. See Apple's
[`SMAppService.register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29)
documentation and the corresponding
[Apple DTS guidance](https://developer.apple.com/forums/thread/783539).

The updater artifact key embedded in 0.3.5 is not available for 0.4.0 signing.
Consequently, 0.3.5 to 0.4.0 is an explicit manual-DMG migration: publish no
legacy-key, dual-signature, alternate-origin, or unsigned compatibility path.
The 0.4.0 archive and its embedded trust configuration use replacement key ID
`233E924581F20ACB`; the signed, notarized, stapled DMG remains the supported
installation artifact.

This updater rotation is independent of the physical collector trust root.
Production physical receipts accept only the source-pinned aggregate v5 /
receipt v3 / proof v3 / trust-policy v3 PS256 contract backed by one versioned Cloud KMS HSM
RSA-3072 key. The checked-in collector policy is configured for the reviewed
v0.4.0 key, attestation, public key, collector source closure and immutable OCI
image digest. External release operations have live-tested the least-privilege
signer, Firestore nonce ledger, Binary Authorization and locked Data Access
audit retention described in
[`docs/release/physical-collector-v040.md`](docs/release/physical-collector-v040.md).
The trust-policy profile is inside the receipt-signed policy digest, so a v4
aggregate or a receipt issued under the former policy digest cannot be
relabelled as v5. This does not close the same-machine, two-clean-OS physical gate or authorize
build 40021. No updater key, Apple notarization key, local private key, or older
RS256 receipt may substitute for this trust root.

On the provisioned release Mac, invoke updater packaging through its executable
entrypoint. Do not prefix it with `bash`: its `#!/bin/bash -p` boundary prevents
`BASH_ENV`, imported functions, and caller shell options from executing before
the custody checks.

```bash
set +x
scripts/make_updater_manifest.sh \
  "$PWD/target/candidates/0.4.0/signed/Clash for Mac.app"
```

The shell entrypoint rejects xtrace, exported shell-option state, startup-hook
variables, dynamic-loader/import/archive environment overrides, and every
current or legacy caller-supplied Tauri secret variable. It resets `PATH`,
resolves one fixed Homebrew Python probe to a canonical interpreter, disables
Python site customization with `-S`, and calls the source-pinned launcher in an
empty, explicit environment with only the archive path.
The launcher verifies the complete fixed Tauri 2.11.4 toolchain tree and signer
digest before requesting the password. It then opens the fixed owner-only key
at `~/Library/Application Support/Clash for Mac Release/Updater/cfw-rs-v2.key`
with `O_NOFOLLOW`, validates the private `~/Library` anchor and every held
path/inode/mode/link/ACL boundary, and reads exactly one non-synchronizable item
from the explicit login Keychain under service
`com.bill.clashformac.release.updater`, account `updater-v2`. Only the final
signer receives the password, in the one environment variable required by
Tauri; neither the password nor a caller-selected key/signer path enters argv.

Release assets do not become uploadable as independent files. The updater
archive, signature, `latest.json`, and the verifier's embedded-public-key
receipt are sealed and atomically published as
`target/candidates/0.4.0/release/updater/vVERSION/`. The DMG, accepted result,
normalized log, private Gatekeeper evidence, submission receipt, and artifact
manifest are sealed and atomically published for release operations as
`target/candidates/0.4.0/release/dmg/vVERSION/`. The canonical seals bind exact
names, sizes, SHA-256 values, version/build/source identity, official URL, and
verification result. Each component seal also binds the exact
`Clash for Mac.app.manifest.json` digest and signed-app tree SHA-256. The
updater verifier reconstructs that v2 tree directly from the compressed tar
bytes. It accepts exactly one gzip member, requires the two-block tar terminator,
rejects non-zero data after logical tar EOF, concatenated members, compressed
suffixes, and unbound PAX metadata. The DMG verifier mounts the final stapled
image read-only and reconstructs the contained app tree. Both recheck the
package bytes and candidate binding after reconstruction, closing the
verify-then-pack race. A partial directory, extra/unknown field, symlink,
hard-link, digest drift, or conflicting pre-existing destination is rejected
rather than overwritten. Each normal or reply-loss publication path fsyncs the
complete sealed destination tree and both rename parents before reporting
success.

After both packaging commands succeed, create the distinct post-packaging
distribution seal, then run the read-only upload-asset gate:

```bash
scripts/release_publication_gate.sh --seal-assets 0.4.0
scripts/release_publication_gate.sh --upload-assets 0.4.0
```

The atomic `release/distribution/vVERSION/distribution-set.seal.json` joins the
same signed app and app manifest to both package seals and every DMG/updater
asset. It also binds the complete publication-evidence tree and records direct
digests for the sealed outer Evidence Manifest, machine closure, inventory,
evidence manifest, legal review, SPDX/CycloneDX SBOMs, and
corresponding-source manifest; the corresponding source archive and all
remaining publication files are transitively bound by
that exact tree digest. The Python `seal-release` operation itself invokes the
authoritative publication verifier before writing this seal and proves the
evidence tree did not change across semantic authorization; correctness does
not depend only on shell call order. The upload gate reruns the semantic publication
verification and then reopens and recomputes this final seal. Only the paths it
prints are eligible for upload; the earlier signed-app publication-evidence
gate or either component seal alone is not upload authorization.

The same atomic distribution directory contains one deterministic public
publication bundle, its canonical sidecar manifest, and the standalone public
Gatekeeper projection. The bundle also contains that exact projection together
with the corresponding-source archive and manifest, SPDX and CycloneDX SBOMs,
publication inventory and evidence manifest, machine closure, the project GPL
license, the 0.4.0 changelog as `MODIFICATIONS.md`, and every reviewed
third-party license/NOTICE file. The upload gate reopens every tar member and
recomputes its path, mode, size, and digest before printing the bundle. The
human `legal-review.json`, raw Gatekeeper evidence, final-candidate evidence,
sealed outer evidence, and raw physical evidence remain required private
release inputs where applicable, but are deliberately excluded from the public
bundle. Public-source admission rejects their reserved filenames/source IDs and
either private visibility marker even if a future change relocates or renames a
document.

GitHub requires every individual release asset to be under 2 GiB. The bundle
therefore has a hard maximum of `2 GiB - 1 byte`; its nested corresponding-source
archive is capped separately at 1.25 GiB, non-CCS inputs at 256 MiB total, and
the remaining capacity is reserved for the canonical bundle manifest and tar/
gzip container overhead. The 15-path upload allowlist is also below GitHub's
1000-asset limit. See [GitHub's release storage and bandwidth quotas](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas).

### Read-only remote publication verification

Before uploading, retain `distribution-set.seal.json` on offline media and
retain its lowercase SHA-256 independently. The trusted seal must be the exact
file that passed the local `--upload-assets` gate; a seal or digest downloaded
from the release being checked is not a trust root. After all 15 allowlisted
assets have been uploaded to the public `vVERSION` GitHub release, run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_remote_release.py \
  --version 0.4.0 \
  --trusted-distribution-seal /path/on/offline-media/distribution-set.seal.json \
  --trusted-distribution-seal-sha256 '<64-lowercase-hex>'
```

This command has no upload, publication, URL-override, token, cookie, or output
file option. Before any network request it requires the current repository to
be clean and its commit plus release-source digest to equal the trusted seal;
a different or dirty verifier checkout fails closed. It then issues
credential-free `GET` requests to the fixed public
`github.com/billlza/cfw-rs/releases/download/vVERSION/` paths, accepts only the
certificate-validated HTTPS transition to GitHub's documented
`release-assets.githubusercontent.com` download host, and requires an exact
200 response, `Content-Length`, sealed size, and SHA-256 for every object. See
[GitHub's release-asset network requirement](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#communication-requirements-for-github-hosted-runners).

Downloads exist only in a mode-0700 temporary directory. Each file is created
through the retained directory descriptor with exclusive, no-follow flags and
is removed after the final second hash pass. The verifier derives the exact
12 release-asset names and size limits from `release_artifact_set`, adds the two
component seals and the trusted distribution seal, and refuses anything other
than exactly 15 unique files. Any redirect drift, partial response, transform,
extra suffix, size mismatch, hash mismatch, symlink/hard-link, or concurrent
mutation fails closed.

Remote verification proves that the public bytes are identical to the offline
distribution seal's already-authorized upload set. It does not replace the
separate local signing, notarization, stapling, Gatekeeper, updater-signature,
physical-runtime, or publication-semantic gates.

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
