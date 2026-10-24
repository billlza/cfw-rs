# macOS release gate

This project releases only an arm64 application for macOS 15 or newer. A green
Rust, JavaScript, or Swift unit-test lane is necessary but does not establish a
releasable Network Extension product.

> **v0.4.0 policy calibration:** the executable ordinary-GA versus assurance
> boundary is recorded in
> [`docs/release/ga-assurance-policy-v040.md`](docs/release/ga-assurance-policy-v040.md).
> The release has one candidate identity: build 40073. Build 40030 is retired
> unbuilt as `retired_unbuilt_policy_superseded`; it must never be rebuilt,
> signed, installed, or used as a validation companion. Build 40031 is retired
> after candidate freeze and a failed private signing attempt, before canonical
> signed output; its immutable history is recorded in
> [`docs/release/ga-build-40031-retirement.md`](docs/release/ga-build-40031-retirement.md).
> Build 40032 is likewise retired after candidate freeze and one terminal
> private signing attempt, before Host signing or canonical output; see
> [`docs/release/ga-build-40032-retirement.md`](docs/release/ga-build-40032-retirement.md).
> Build 40033 is likewise retired after candidate freeze and one terminal
> private signing attempt; its distribution-mode failure occurred before Host
> signing or canonical output. See
> [`docs/release/ga-build-40033-retirement.md`](docs/release/ga-build-40033-retirement.md).
> Build 40034 is likewise retired after candidate freeze and one terminal
> private signing attempt. Its nested roles and outer Host were signed, but a
> post-sign Tombstone manifest schema mismatch stopped the transaction before
> canonical output or notarization. See
> [`docs/release/ga-build-40034-retirement.md`](docs/release/ga-build-40034-retirement.md).
> Build 40035 is likewise retired after candidate freeze and one terminal
> private signing attempt. Complete private signed-output verification failed
> before canonical output or notarization; the durable journal does not support
> a narrower root-cause claim. See
> [`docs/release/ga-build-40035-retirement.md`](docs/release/ga-build-40035-retirement.md).
> Build 40036 completed canonical signing, Apple notarization, stapling, and
> Gatekeeper assessment, then retired before install because publication
> contract corrections changed its frozen release-source/product-input identity.
> See
> [`docs/release/ga-build-40036-retirement.md`](docs/release/ga-build-40036-retirement.md).
> Build 40037 likewise completed candidate freeze and one private signing
> attempt. The helper returned success and wrote a complete transformation
> receipt, but a later mandatory read-only replay failed before publish-ready,
> canonical output, or notarization. Its frozen terminal history is recorded in
> [`docs/release/ga-build-40037-retirement.md`](docs/release/ga-build-40037-retirement.md).
> Build 40038 likewise completed candidate freeze and one private signing
> attempt. The helper returned success, but the attempt failed before a
> transformation receipt, canonical output, or notarization was durably
> created. Its frozen terminal history is recorded in
> [`docs/release/ga-build-40038-retirement.md`](docs/release/ga-build-40038-retirement.md).
> Build 40039 completed freeze and canonical signing, then its notarization
> submission ended with an unknown outcome. The required SOCKS5 product changes
> cannot be added to those frozen bytes. Its consumed lineage is retired while
> the original notarization transaction remains quarantined; see
> [`docs/release/ga-build-40039-retirement.md`](docs/release/ga-build-40039-retirement.md).
> Build 40040 completed freeze and canonical signing, but two subsequently
> published SSH advisories require an `x/crypto` dependency change. It is
> retired before any Apple submission, with its original bytes and receipts
> preserved; see
> [`docs/release/ga-build-40040-retirement.md`](docs/release/ga-build-40040-retirement.md).
> Build 40041 completed notarization, packaging and the 40019→40041 install,
> but GA runtime acceptance could not be collected: the application's legacy
> cutover preflight attributed the live Clash for Windows network to the
> retired installation, and acceptance requires that network to be preserved.
> It is retired after install with its bytes, receipts, seals and journals
> preserved; see
> [`docs/release/ga-build-40041-retirement.md`](docs/release/ga-build-40041-retirement.md).
> Build 40042 was frozen, signed and notarized, but its own frozen source
> cannot pass the local lane reproduction: one release-tooling test read the
> ambient toolchain selection the lane collector exports. It is retired after
> notarization with its bytes and receipts preserved; see
> [`docs/release/ga-build-40042-retirement.md`](docs/release/ga-build-40042-retirement.md).
> Build 40043 completed signing, notarization, packaging and the 40041→40043
> install. Before GA runtime collection started, importing authenticated
> profiles exposed a product defect: the native credential receipt encoded an
> uppercase profile UUID that the Rust consumer correctly rejected. The error
> was also misclassified as vault corruption. The correction changes shipped
> application code, so 40043 is retired after install with all original
> evidence preserved; see
> [`docs/release/ga-build-40043-retirement.md`](docs/release/ga-build-40043-retirement.md).
> Build 40044 completed signing, notarization, both package sets and the
> 40043→40044 installation. Its migration handoff child then exited when the
> normal parent exit was misclassified as a kernel process-identity failure.
> Correcting this product code required successor 40045. The 40044 application,
> packages, receipts and installation journals remain unchanged; see
> [`docs/release/ga-build-40044-retirement.md`](docs/release/ga-build-40044-retirement.md).
> Build 40045 completed application notarization and the 40044→40045 install.
> The requested normal-start behavior removes mandatory legacy migration
> preparation and confirmation, and rejects a real foreign System Proxy
> conflict without changing that owner's settings. These application changes
> require successor 40046. All 40045 bytes, source/legal evidence and journals
> remain preserved; see
> [`docs/release/ga-build-40045-retirement.md`](docs/release/ga-build-40045-retirement.md).
> Build 40046 completed installation but omitted the real compiled runtime.
> Its native runtime and profile-display repairs shipped in 40047; see
> [`ga-build-40046-retirement.md`](docs/release/ga-build-40046-retirement.md).
> Build 40047 completed installation but still blocked explicit System Proxy
> takeover and service recovery. Those product corrections shipped in 40048; see
> [`ga-build-40047-retirement.md`](docs/release/ga-build-40047-retirement.md).
> 40048 exposed authorization waiting inside engine startup and a late-disconnect
> crash. Their fixes require 40054; see
> [`ga-build-40048-retirement.md`](docs/release/ga-build-40048-retirement.md).
> Build 40054 passed installed System Proxy start and restoration, then exposed
> an obsolete Tunnel credential encoding at the Authority boundary. The product
> correction required 40055; see
> [`ga-build-40054-retirement.md`](docs/release/ga-build-40054-retirement.md).
> Build 40055 reached first-time VPN consent and the real Provider, exposing a
> five-second human-consent deadline and the wrong provider-start API. The
> corrections were included in 40061; see
> [`ga-build-40055-retirement.md`](docs/release/ga-build-40055-retirement.md).
> Build 40061 was signed, notarized and installed. The approved client-parity
> product changes require 40062; see
> [`ga-build-40061-retirement.md`](docs/release/ga-build-40061-retirement.md).
> Build 40062 completed installation but exposed native command and editing
> failures. Their product corrections require 40063; see
> [`ga-build-40062-retirement.md`](docs/release/ga-build-40062-retirement.md).
> Build 40063 completed installation and local proxy checks, then exposed
> stale heartbeat and stop deadlines crossing owner generations. Their
> native product correction requires 40064; see
> [`ga-build-40063-retirement.md`](docs/release/ga-build-40063-retirement.md).
> Build 40064 completed installed local and pure-TUN traffic checks, then
> exposed rejected owner stop proofs after a system VPN disconnect. Build
> 40065 fixes that state transition and adds an IPv6 DNS preference for
> IPv4-only exits while retaining IPv6 packet capture; see
> [`ga-build-40064-retirement.md`](docs/release/ga-build-40064-retirement.md).
> Build 40065 passed installed local, pure-TUN and combined proxy traffic,
> but reconnect after a system VPN stop retained an already released owner.
> Build 40066 corrects that coordinator contract; see
> [`ga-build-40065-retirement.md`](docs/release/ga-build-40065-retirement.md).
> Build 40066 completed signing and notarization. Before installation,
> native stop regressions also required exact completed-generation handling
> when a Host missed the final status observation. This requires 40067; see
> [`ga-build-40066-retirement.md`](docs/release/ga-build-40066-retirement.md).
> The compatible dependency refresh changes the engine and native product inputs,
> requiring 40068. Its frozen predecessor remains preserved; see
> [`ga-build-40067-retirement.md`](docs/release/ga-build-40067-retirement.md).
> Build 40068's TUN start then exposed a ticket expiry during macOS extension
> startup. The product correction requires 40069; installed 40068 and its
> notarization evidence remain preserved. See
> [`ga-build-40068-retirement.md`](docs/release/ga-build-40068-retirement.md).
> Build 40069 works for the user. The direct IPv6 DNS switch and correction of
> manual-preference precedence change application code and require 40070; see
> [`ga-build-40069-retirement.md`](docs/release/ga-build-40069-retirement.md).
> Build 40070 was signed, notarized, stapled and installed. A supported M5
> MacBook Air then exposed a black, unresponsive dashboard at launch. Bounding
> renderer presentation and startup waits changes application bytes and requires
> 40071; see
> [`ga-build-40070-retirement.md`](docs/release/ga-build-40070-retirement.md).
> Build 40071 was signed, notarized, stapled and installed. Live paired probes
> then showed its SOCKS setup expiring after five seconds while the same node
> completed negotiation and delivered HTTPS responses with a longer budget.
> Correcting the protocol setup budget changes libbox bytes and requires 40072;
> see [`ga-build-40071-retirement.md`](docs/release/ga-build-40071-retirement.md).
> Build 40072 completed signing, notarization and local installation. Adding
> four UI languages, native menu localization and persisted language selection
> changes application bytes and requires 40073; see
> [`ga-build-40072-retirement.md`](docs/release/ga-build-40072-retirement.md).
> A passing policy or source check alone does not consume the active GA build. Its
> first durable candidate freeze does, after which only supported recovery may
> reuse those exact frozen bytes and their append-only transaction identities.

The project-wide build-number design rule is
[`docs/release/candidate-identity-lifecycle.md`](docs/release/candidate-identity-lifecycle.md#build-number-allocation-and-consumption).
`CFBundleVersion` identifies one application-candidate lineage; it is not a
source-gate, CI, preflight, packaging, or evidence retry counter. Before any
allocation change or retirement proposal, the author and reviewer must use the
decision table in that document and record whether candidate freeze, signing,
installation, notarization, or another externally observable action may have
started. Pre-candidate failures use append-only attempt or CI-run identities
and must not consume another application build.

After consumption, the build remains bound to one immutable candidate. An
evidence-only retry keeps the same `CFBundleVersion` and records a new evidence
identity; a product-input, application, entitlement, profile, or
application/nested-code signature-byte change retires the lineage and requires
a successor. DMG/updater envelope signatures use package-attempt identities,
not new application builds. An ambiguous external outcome is quarantined and
recovered from its original transaction identity; allocating another build is
not a recovery mechanism.

A changed whole-repository commit or release-source checksum does not by itself
establish a product change. In particular, the test-isolation failure recorded
for retired 40042 is historical evidence of a workflow limitation, not a rule
for retiring later candidates. Preserve the active GA candidate while repairing
evidence tooling.
The current frozen product-input v1 document includes the complete source
identity; its digest cannot alone distinguish product and evidence changes.
Do not relabel that document or claim that a newer test suite ran at its commit.
An unsupported evidence-only repair remains an explicit evidence failure until
its executor and product-input boundary are implemented and verified; it does
not automatically authorize another build number.

Android and iOS are not release targets. Physical interoperability may use an
iOS device as a test peer, but its harness, device identity, transport capture,
and receipts must be independently source-bound.
The repository's test-only iOS transport peer remains outside the product and
release bundle. The iPhone Packet-LAN mode is the only `lan-bypass` evidence
source; the legacy Android packet peer, its ADB pin, and its CI lane were
removed, and none of their historical receipts is reusable. No prior pilot is
reusable either: every assurance capture requires a fresh dynamic ready address,
three joint Mac/iPhone connection bindings, pcap/Host evidence, and exact
cleanup.
The ordinary macOS environment gate verifies the checked-in iOS peer source
identity without requiring its generated app, provisioning profile, or signing
entitlements. The actual assurance admission owns those artifact and device
checks; missing iPhone infrastructure does not block ordinary macOS GA.

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

The libbox input is upstream sing-box `SING_BOX_VERSION` at commit
`SING_BOX_COMMIT` plus six digest-pinned repository
patches: security dependency updates, the public raw-packet adapter, bounded
DNS failover, structured loopback endpoint-conflict reporting, isolated profile
probes, and SOCKS lifecycle/concurrency corrections. Each patch path and
digest, the exact combined diff (`SING_BOX_COMBINED_DIFF_SHA256`), and the
patched `go.mod`/`go.sum` digests are release inputs in
`scripts/dependency_pins.env`, the authoritative store of pinned values;
`scripts/pinned_build_inputs.json` holds the policy those values must satisfy.
This runbook names pin keys, never their values; `docs/supply-chain.md` lists
the few verified copies that remain. The previous helper, mihomo, clash-rs,
downloaded core, and private packet-flow file-descriptor access are not
fallbacks.

The compatible dependency refresh pins `golang.org/x/mod v0.41.0` and
`golang.org/x/crypto v0.57.0`. The 2026-10-08 Go security releases moved the
compiler (`GO_VERSION`) and the module's minimum Go version past `1.27.1` and
`golang.org/x/net` to `v0.60.0`; the scan had reported reachable standard
library and `x/net` HTTP/2, HTTP/1, MIME header and `crypto/tls` findings in
`1.27.1` and `v0.59.0`, and `html/template` findings in an imported package
whose affected code the engine does not call. The 2026-10-21 `GO-2026-6809`
release (a `crypto/x509` denylist of distrusted intermediates) moved both again,
and `RUSTSEC-2026-0382` for the same intermediates moved `rustls-webpki` to
`0.103.16`. The SOCKS correction
materializes a checksum-bound
private build workspace containing the corrected `sing v0.9.4` source while
preserving the original module cache. The release vulnerability scan checks
both the original versioned dependency graph and the corrected workspace,
and must report zero affected symbols and zero affected imported packages
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
`block`, SOCKS5, Shadowsocks, VMess, VLESS/Reality, Trojan, Hysteria2, AnyTLS, and TUIC
v5 outbounds; it must not be marketed as full sing-box configuration support.
Profile JSON may contain immutable canonical credential references, including
separate TUIC UUID and password references, but never secret bytes.
The source implements missing-only shared-Keychain provisioning, presence
checks, authenticated in-memory native slot injection, and revision-bound
orphan cleanup. Release remains blocked until those paths pass under installed
signed Host/ProxyAgent/System Extension identities on physical machines.
Legacy data cleanup is optional maintenance. Normal System Proxy and TUN
starts directly report actual ownership, permission, credential or recovery
errors; an unfinished cutover transaction still requires explicit recovery.

Each durable Authority journal generation is bounded to 4,096 records and
32 MiB. Before a prepare would consume the seven-record lifecycle finish
reserve, the store commits a hash-chained checkpoint into the next anchored
generation and retains only the active and previous generations. Recovery
fails closed on rollback, malformed generation state, an insecure cleanup
target, or cleanup failure. Deterministic fault-injection tests cover every
checkpoint commit and obsolete-generation cleanup crash boundary; those source
and unit-test claims do not replace the physical-machine longevity and soak
gates below.

Launching the app must never stop or mutate another VPN, System Proxy, routes,
or DNS. Normal mode controls do not prepare or confirm legacy retirement. A
release candidate must prove that replacement profiles can be staged under
`sing-box-profiles-v1` while historical `profiles` state remains untouched.
The optional legacy-maintenance entry keeps its explicit deletion confirmation
and server-side native/profile checks before the one-way tombstone is reachable.

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
- one physical Apple Silicon test Mac with a fixed supported macOS environment
  for ordinary GA; a second clean-OS environment belongs to assurance-only
  qualification.

`verify_release_environment.sh` rejects `.key`, `.pem`, or `.p8` material under
the repository workspace, apart from the managed caches described under
[Release-worktree preparation](#release-worktree-preparation). Git ignore rules are not a key-management boundary:
the active updater key must live in an access-controlled external secret store
or hardware-backed workflow. If a workspace copy may have escaped through a
backup or shared archive, rotate the key and publish an explicit updater trust
migration before release.

## Release-worktree preparation

The artifact checkout is a detached Git worktree at the fixed path
`target/release-worktrees/$CFW_GA_BUILD` of the operator checkout
(`CFW_GA_BUILD` is the active GA build of `scripts/release_identity.env`; see
[the GA release sequence](#single-ga-release-sequence)). Create its untracked
`target` directory with mode `0700` before copying the managed dependency
inputs into it. The path/name-only secret-material gate excludes the managed
`debug`, `native-dependencies`, `release-build-cache`, `sources`, `toolchains`
and `ui-build` children of every `target/release-worktrees/<five-digit
build>/target`, including retained retired worktrees, by path and name, exactly
as it excludes them from the operator checkout's own `target`. Source files,
candidate trees and every other target child remain in the secret scan. A
managed name that is not a real directory owned by the workspace owner fails
closed, and so does an alias into an excluded cache. The gate keeps no record
of the worktree, so neither a reboot nor a recreated worktree needs a recovery
step. Cache-scope receipt, recovery, pending and lock files that earlier tools
wrote into the operator's `.git/worktrees/<name>/` entries are no longer read
by this revision; leave them in place, because the release tools of older
frozen commits still read them.

Before candidate freeze, a source correction may require a new detached HEAD.
After proving that no candidate freeze or external transaction started, retain
the complete failed preparation with `git worktree move` in a new private
history path outside the main workspace. Preserve its source, generated inputs
and attempt logs. Recreate the fixed `target/release-worktrees/$CFW_GA_BUILD`
path at the verified new commit, create its `target` with mode `0700`, then
copy and revalidate the managed dependency inputs. Git may give the new administrative directory a numeric
suffix (for example `400491`); nothing depends on that suffix.
This is another preparation attempt using the same active GA build, not
candidate retirement or a new build allocation.
These reversible checkout, input-copy and environment-preflight
steps may run while hosted CI runs for the same source commit; the candidate
build starts only after that run has passed (step 1 below). Required local
source/build admission checks still run before candidate freeze and signing. The successful exact-source hosted receipt
is required where publication preparation and prepackage consume that evidence.

## 1. Prepare and seal networked release inputs

Before invoking a closed release entrypoint, separately prepare the fixed Rust
SDK at the effective account's
`~/.cfm-release-tooling/rust-toolchains/$RUST_VERSION-aarch64-apple-darwin`,
where `RUST_VERSION` comes from `scripts/dependency_pins.env`.
This deployment/bootstrap step precedes environment consumption; release
commands verify an existing SDK and never create, install, repair, or replace
it automatically. On the release Mac, explicitly select `private` for input
preparation, signing, evidence collection, packaging, and publication:

```sh
export CFW_RELEASE_RUST_TOOLCHAIN=private
./scripts/run_release_ci_gate.sh prepare-cargo-workspace-inputs
./scripts/run_release_ci_gate.sh bootstrap-policy-tools
./scripts/run_release_ci_gate.sh bootstrap-release-toolchain
tauri_install_tmp="$(/usr/bin/mktemp -d /private/tmp/cfw-tauri-install.XXXXXX)"
/bin/chmod 0700 "$tauri_install_tmp"
TMPDIR="$tauri_install_tmp" ./scripts/run_release_ci_gate.sh install-tauri-cli
/bin/rmdir "$tauri_install_tmp"
./scripts/run_release_ci_gate.sh prepare-ui-dependencies
./scripts/run_release_ci_gate.sh fetch-libbox-upstream \
  /absolute/path/to/clean-upstream-sing-box
./scripts/run_release_ci_gate.sh materialize-libbox-source \
  /absolute/path/to/clean-upstream-sing-box \
  /absolute/path/to/patched-sing-box
./scripts/run_release_ci_gate.sh prepare-libbox-modules \
  /absolute/path/to/patched-sing-box
```

`CFW_RELEASE_RUST_TOOLCHAIN=global` retains the existing CI SDK location,
`~/.rustup/toolchains/$RUST_VERSION-aarch64-apple-darwin`. Only an unset bootstrap
selection defaults to `global`; the sealed environment always records an
explicit `global` or `private` selection. Neither selection accepts arbitrary
paths or falls back to the other SDK on failure. Both require the same exact
six-component `rustup-component-file-tree-v2` surface and unchanged
`RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256` pin. `CFW_TOOLCHAIN_ROOT` selects
the other managed tool trees and does not select Rust.

Frozen build 40043 retains its original global-only launcher. Its low-level
Rust surface contract can verify an identical SDK at another canonical root,
but the new selector does not change that old launcher's path admission or
make a complete historical replay portable. Its source and receipts remain
unchanged.

The Tauri installer requires its explicit `TMPDIR` to be a canonical,
current-user-owned directory that is not writable by group or other users.
Remove only the exact empty directory created by the command above; do not use
the shared `/private/tmp` directory itself as the installer input.

`prepare-cargo-workspace-inputs` is the only networked admission path for the
Rust workspace dependency sources. It fetches every `Cargo.lock` registry
archive into a fresh private Cargo home, checks each archive against the lock
file checksum, rejects unsafe archive contents, and records an archive-derived
manifest for the complete vendor tree. Every later Cargo command that resolves
or builds the workspace graph re-derives the vendor contents from those
authenticated archives before and after use and runs through a fresh private
runtime configuration; an ambient Cargo source directory or configuration is
never a release input.

Release preparation, build, and publication must run in a quiescent,
single-operator maintenance window on a trusted release account with a trusted
ACL state. Owner-owned, non-group/other-writable POSIX modes plus archive-derived
revalidation detect persistent or static drift; they do not claim to defeat code
already executing concurrently as the release UID, which could also race the
repository, build outputs, or signing process.

Apart from two credential-custody checks, the release tools' read, hash,
tree-walk and fsync stability checks never compare the status-change time. They
compare at least device, inode, size and modification time, and most also mode
and link count, plus owner where a reader enforces it. macOS changes the
status-change time without touching any byte, for example when it rewrites
`com.apple.macl` on an application root about 40 ms after an atomic swap. A
rename changes only that time, so identities are compared whole across a
rename. Content changes still move the size, modification time, inode or link
count, and the final bytes are hashed again at packaging and upload. The two
exceptions detect ACL, flag and extended-attribute drift on key material: the
updater-key record persisted as `changedNs` in the signing preflight manifest,
and the updater signing launcher's in-process credential path identities.

Review [`docs/supply-chain.md`](./docs/supply-chain.md). Verify that the release
commit, submodule/reference state, version, changelog, and complete
corresponding-source candidate are immutable and have recorded SHA-256 hashes.

## 2. Verify the sealed inputs and build libbox offline

Preparation is explicit and networked; the release build is offline:

```sh
./scripts/verify_release_environment.sh
./scripts/run_release_ci_gate.sh build-script-boundary
./scripts/run_release_ci_gate.sh rust-metadata
./scripts/run_release_ci_gate.sh libbox-vulnerability-scan \
  /absolute/path/to/patched-sing-box
./scripts/run_release_ci_gate.sh build-libbox \
  /absolute/path/to/patched-sing-box
```

Release-critical shell entrypoints rebuild one closed execution environment
from the effective macOS account rather than caller `HOME` or `PATH`.
Production signing, publication, and physical-evidence entrypoints accept only
the exact Rust SDK selected above and the Homebrew Cellar path of
`PYTHON_VERSION`. Only the
unsigned validation entrypoints, build 40000 and the unsigned preview build
50000, may accept the absolute Python executable emitted by the SHA-pinned
`setup-python` action; it verifies the same exact version and
real executable/runtime identities and includes their content digests in the
toolchain binding. Developer-ID and publication paths reject that selection.
The environment keeps system Git/Bash/Zsh ahead of the owner-only, versioned
policy-tool directory, validates one pinned Xcode Developer tree, and content-binds every
executable used by the CI toolchain identity. Newly executed lane logs remain
in an isolated attempt journal until the ending identity matches the starting
identity; output beyond the fixed 64 MiB streaming limit terminates the
complete lane process group.

The Tauri installer verifies the official `TAURI_CLI_VERSION` crate and its unchanged published
lock, and installs only from that local source with `--locked` using isolated Cargo
home and target directories. It normalizes only Cargo's three exact root-level
runtime tracking/lock files in the private offline cache copy, then proves the
complete remaining registry tree is byte-identical before and after compilation.
The normalization helper digest and policy are bound into the final toolchain
manifest, and any fetch or install warning blocks the bootstrap. The sealed
payload contains only its thin arm64 binary and clean official crate source, lock, and licenses under
`target/toolchains/tauri-cli-$TAURI_CLI_VERSION`. Release scripts invoke that absolute
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
./scripts/run_release_ci_gate.sh rust-fmt
./scripts/run_release_ci_gate.sh rust-clippy
./scripts/run_release_ci_gate.sh rust-test
./scripts/run_release_ci_gate.sh rust-target-audit
./scripts/run_release_ci_gate.sh cargo-deny
./scripts/run_release_ci_gate.sh ui-test
./scripts/run_release_ci_gate.sh ui-build
./scripts/run_release_ci_gate.sh ui-audit
./scripts/run_release_ci_gate.sh swift-format-lint
./scripts/run_release_ci_gate.sh swift-package-test
./scripts/run_release_ci_gate.sh xcode-unsigned-test
./scripts/run_release_ci_gate.sh xcode-analyze
```

Every command must complete without project-owned errors or warnings. Upstream
advisories without a safe compatible release remain release blockers unless the
dependency is proven unreachable in the shipped target and the project owner
accepts the exact documented boundary; advisory IDs are never silently ignored.
`rust-target-audit` derives the exact `aarch64-apple-darwin` all-features resolve
graph before running `cargo-audit` with vulnerability and warning advisories
denied. It disables only cargo-audit's duplicate per-package yanked query.
`cargo-deny` is the sole owner of current yanked status and consumes that same
closed target metadata: bans, licenses and sources are evaluated against the
verified offline Cargo inputs, while advisories and yanked status use a fresh
private, bounded online policy-data directory that is deleted after the check
and never becomes a compiler input. Its fixed policy explicitly denies yanked
packages and forbids disabling yank checks. Its JSON output must contain one
zero-error, zero-warning, zero-note summary and no diagnostic records. Both
gates are mandatory; neither can authorize release alone. A dependency that
resolves in the shipped target remains blocking.

## 4. Native data-plane evidence

Run the signed app on one controlled physical Apple Silicon Mac, sequentially
booted into the two source-pinned clean OS environments. Both runs must bind
the same machine identity while retaining distinct run IDs, nonces, receipts,
and raw archives. Capture unique per-test tokens and packet evidence for TCPv4,
TCPv6, UDP/QUIC, DNS A/AAAA, LAN bypass, included routes, and excluded routes.
A connected VPN status or an existing `utun` interface is not data-plane
evidence.

The receive-only Packet peer under `tools/packet-evidence-endpoint/` is built
with its own Go toolchain (`PACKET_EVIDENCE_ENDPOINT_GO_VERSION`,
`PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256`), not the product's
`GO_VERSION`, into a reproducible Linux/amd64 binary whose digest is
`PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256`. A product Go bump leaves it
unchanged; an endpoint Go bump is a separate change that rebinds the binary
pin, the installer, the endpoint identities and policy, and the digests that
record them (the installer and policy digests in `packet.py`, the verifier and
the `packetEvidenceEndpoint` source digests, and the identity digests in
`scripts/harness/packet_evidence.py`). The endpoint pins live in
`scripts/dependency_pins.env`, so any endpoint rebinding also changes that
file's digest, which the CI toolchain binding, the native UI source digest and
the release verifier's inputs record: after a freeze it is not an
evidence-only change. The digests of its sole Debian
installation transaction (`install-endpoint.sh`), systemd unit, fixed GCE
resolver and exact capture sudoers are the `packetEvidenceEndpoint` source
digests in `scripts/pinned_build_inputs.json`; this document does not repeat
them.
GA runtime acceptance uses the endpoints only as DNS and TCP/UDP peers and
does not depend on the deployed binary's identity, so a rebinding does not
block GA. Physical assurance evidence binds the identity, and its collection
requires the VMs to run the pinned binary first: rerun the installation
transaction on each instance.
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
A syntactically legal pcap, live endpoint, prior pilot, or manual capture cannot
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

Before it claims the attempt, the app notarization transaction runs
`syspolicy_check notary-submission` once as advisory evidence. The local result
never blocks submission, and no macOS build identity is consulted. Apple's
verdict decides: the Accepted notarytool status, the retained notary log and
the stapled ticket. The local checks after it, stapler validation, the
Gatekeeper assessment and the final `syspolicy_check distribution`, all still
fail closed. Attempt schema v5 records the local result in `intent.json` as
`notary_readiness_advisory`:

- `completed` keeps the exit status, a stderr class (`none`,
  `single-signature` or `other`), and for each finding its level and short
  error when they are short tokens, and its app-relative file;
- `unrecognized-output` keeps the exit status and stderr class when the output
  is not the expected findings document;
- `unavailable` names why no recordable result exists: a bounded-runner code
  such as `command_start_failed` when the tool is missing, or
  `notary-readiness_advisory_output_oversized` when stdout exceeds 256 KiB.

Free-form command text and paths outside the app are never persisted, and the
record is checked against the recovery validator before the claim. A
release-host fault, such as process cleanup that cannot be confirmed, still
stops the transaction before the claim. The second journal event,
`notary_ready`, now means that pre-submission admission finished; it no longer
implies that the local check passed. Tooling at this revision reads only
attempt schema v5, so verify any older attempt with the commit that produced
it.

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
Both commands first run `scripts/verify_release_app.sh` in its default live
mode. That gate requires the
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

- `target/candidates/0.5.0/ga/$CFW_GA_BUILD/signed/Clash for Mac.app` as the signed binary root;
- `target/candidates/0.5.0/ga/$CFW_GA_BUILD/stage-inputs/publication` as the final evidence root.

The gate sources `scripts/release_identity.env` and passes `CFW_GA_BUILD` to the
pure path contract; no packaging script names a build.

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

Explicit recovery has no cumulative attempt-count limit. The journal remains
bounded to 64 events: a full recovery reserves nine events, reconciliation of
an already published set reserves one, and re-verifying a completed transaction
needs none. Capacity is checked before pending-event repair, temporary-output
cleanup or Apple queries. Insufficient capacity preserves the existing journal
and outputs and blocks that evidence operation; it does not retire the app.
If a recovery is interrupted after recording its start, another explicit
recovery records a new start and observes the same submission ID. The previous
start remains in the journal; the DMG is never resubmitted.

Run these commands from the clean operator checkout after the exact app has
been signed, notarized, and stapled. Tools use the fixed frozen checkout for
all product inputs and outputs:

```bash
source scripts/release_identity.env
source scripts/dependency_pins.env
publication_artifact_repository="$PWD/target/release-worktrees/$CFW_GA_BUILD"
publication_ga="$publication_artifact_repository/target/candidates/0.5.0/ga/$CFW_GA_BUILD"
publication_inputs="$publication_ga/stage-inputs"
publication_libbox="$publication_artifact_repository/target/sources/sing-box-$SING_BOX_VERSION-patched"

scripts/prepare_publication_evidence.sh review-template \
  --libbox-source "$publication_libbox"

# Resolve every item in component-review.json and every source blocker, then:
scripts/prepare_publication_evidence.sh prepare \
  --libbox-source "$publication_libbox" \
  --reviewed-components "$publication_inputs/component-review.json"

scripts/run_publication_evidence.sh draft \
  --prepared "$publication_inputs/publication-prepared" \
  --app "$publication_ga/signed/Clash for Mac.app" \
  --output "$publication_inputs/machine-closure.draft.json"

# A human legal reviewer must approve the exact printed closure digest and
# component set in "$publication_inputs/legal-review.json".
scripts/run_publication_evidence.sh finalize \
  --prepared "$publication_inputs/publication-prepared" \
  --app "$publication_ga/signed/Clash for Mac.app" \
  --review "$publication_inputs/legal-review.json" \
  --output "$publication_inputs/publication"

scripts/release_publication_gate.sh --seal-prepackage
```

Previously approved component decisions can be reused after the exact checks
described in [the supply-chain review policy](docs/supply-chain.md). Preserve
the old approval and record the comparison separately. The current closure
record must name its own digest and current release authorization; it must not
pretend that the earlier reviewer saw a subsequently rebuilt source archive.

### Single-GA release sequence

The canonical allocation ledger is
[`docs/release/build-allocations-v050.json`](docs/release/build-allocations-v050.json);
the closed v0.4.0 ledger
[`docs/release/build-allocations-v040.json`](docs/release/build-allocations-v040.json)
retains the earlier history and is only read. The build-boundary gate rejects
any active validation/final pair or any change to an immutable retired prefix.
Builds 40021 through 40029 retain their historical retirement records and
artifacts; none may be relabelled, rebuilt, resubmitted, installed, or reused.
Build 40030 is retired unbuilt by policy. The consumed 0.5.0 preview
validation lineages 50001–50025 form the fixed prefix of the v0.5.0 ledger.
Every retired GA build, in either ledger, keeps its cause, consumed lineage and
retained evidence in its own `docs/release/ga-build-<build>-retirement.md`;
those notes, not this guide, are the per-build history. The original v0.5.0
identity plan is recorded in
[`docs/release/ga-identity-plan-v050.md`](docs/release/ga-identity-plan-v050.md).

The sole `active_ga` identity is 0.5.0 build `CFW_GA_BUILD` of
[`scripts/release_identity.env`](scripts/release_identity.env). Release tools
read it from there: Python through the byte-strict loader in
`scripts/release_build_identity.py`, release shell entry points by sourcing the
file next to `scripts/dependency_pins.env`. Load it into the operator shell
before the commands below:

```bash
source scripts/release_identity.env
```

The migration predecessor is the active predecessor: the newest
`SUPPORTED_PREDECESSORS` profile in `scripts/dormant_app_install.py` whose
build is below `CFW_GA_BUILD`. Install admission accepts only that profile,
verified by product version, build number and installed signed-tree digest.
The SwiftUI dashboard library is signed as one more nested component. Local
installation and smoke testing do not require the public-release evidence or
claim GA acceptance.

#### Allocating a GA build

Retiring the active GA build `N` and allocating `N+1` follows the decision
table in
[`docs/release/candidate-identity-lifecycle.md`](docs/release/candidate-identity-lifecycle.md#build-number-allocation-and-consumption)
and needs the release owner's approval. These are the allocation files:

1. `scripts/release_identity.env`: `CFW_GA_BUILD=N+1`;
2. `docs/release/build-allocations-v050.json`: give `N`'s record its exact
   retired status, append `{"build":"N+1","role":"ga","status":"active_ga"}`
   and set `active_ga` to `N+1`, keeping canonical JSON;
3. `docs/release/ga-build-N-retirement.md`: a new note whose classification
   sentence opens a line as ``GA build N is permanently classified as
   `<status>`.`` with that exact ledger status;
4. `scripts/dormant_app_install.py`, only when `N` was installed on the release
   Mac (an `*_after_install_*` status or
   `retired_superseded_by_next_product_version`): add `N`'s
   `PredecessorProfile` with its retained installed tree SHA-256 to
   `SUPPORTED_PREDECESSORS`. `N` then becomes the active predecessor.

No other file belongs to an allocation; dating the changelog is part of the
release commit (below). The runtime migration admission compares the bundle
installed at the canonical path with the build its executable was compiled as,
which `build.rs` injects from the validated `CFW_BUILD_NUMBER`; release
observations accept any canonical build of the product version and are bound
to the frozen candidate by their consumers.

`./scripts/run_release_ci_gate.sh build-script-boundary` then verifies the
allocation: the ledger must end with the identity file's build as its one
`active_ga`; every record between the fixed prefix and that tail must be a
retired GA with its exact retirement note; no retirement note may exist for a
build at or above the active GA; every installed retired GA must have a
registry profile; and every 0.5.0 registry profile must be an allocated build
below the active GA. Candidate
freeze applies the same rules to the artifact repository, so a missing
predecessor profile fails before signing. The release-tool tests derive every
build from the identity file and the ledger, and an allocation audit rejects
any other tracked file of the release source closure, apart from `docs/` and
the top-level guides, that names a GA-role ledger build outside a digest or
object-ID token, and any installed tree digest outside the registry.

#### Running a release with the driver

`scripts/cfm_release.sh` is the only operator entry point of a release. It
reads the active identity, keeps everything of one GA build under
`~/.cfm-release-tooling/releases/<version>/` (the operator checkout
`operator-<build>` with its artifact worktree, numbered logs, driver records,
the private review files and the retained history), and recognises each stage
as complete from the artifacts the release tools publish:

```bash
scripts/cfm_release.sh status
scripts/cfm_release.sh next
scripts/cfm_release.sh run STAGE
```

`next` names the one stage the recorded state allows, who runs it and what it
needs. `run` refuses a stage that is complete or out of order, then checks both
checkouts, other running release commands, the pinned Xcode and free space, and
runs the stage's fixed entry point in the closed release environment. Only one
`run` of a release proceeds at a time. A partly complete stage, such as a
frozen but unsigned candidate or an unfinished runtime collection, is explained
by `next` instead of being offered again; only its documented recovery runs.
Instructions therefore always come from the artifact state, never from an
earlier message, log or runbook. A refusal is one `refusing:` line whose exit
status names its cause (2 usage, 94 network, 95 another release command or
machine state, 96 a missing prerequisite, 97 a checkout); a release tool's own
failure keeps its exit status. Before pushing a release commit,
`scripts/cfm_release.sh preflight` runs the CI workflow's inline content checks
(shell syntax and the pinned ShellCheck), which no gate lane covers.

| Stage | What it runs |
| --- | --- |
| `enroll` | the operator clone and artifact worktree at the release commit, and APFS clones of the managed inputs of a development worktree whose gates passed on that commit |
| `prepare` | `verify_release_environment.sh`, the preparation lanes and the libbox vulnerability scan in the artifact checkout |
| `ci` | `run_hosted_ci_preflight.sh` (step 1): the newest hosted run of the exact release commit must have passed every check of the receipt |
| `build` | `build_signed_candidate.sh --ga` (step 2; the owner answers the Keychain prompts), and afterwards only the recoveries of step 4 |
| `receipt` | `release_publication_gate.sh --capture-hosted-ci` with the run that `ci` selected (step 3) |
| `review-template`, `review` | the component review template; the approved decisions of the last shipped release carry forward (`scripts/publication/review_carryover.py`) and the owner decides every new or changed manual item |
| `publication-prepare`, `draft`, `legal-review`, `finalize`, `preserve` | the publication evidence of step 5; the owner approves the exact closure |
| `seal-prepackage`, `dmg`, `updater` | the prepackage seal and both package sets of step 5 |
| `install`, `export` | the transactions of step 6 in order, resumed after the last recorded one |
| `acceptance`, `seal-ga-acceptance` | the runtime collector of step 7 and its seal; the driver first checks every precondition the collector would reject after launch, starts the evidence instances and always stops them again |
| `seal-publication`, `publish`, `verify-remote` | steps 9 and 10 and the remote verification below; the owner uploads the allowlisted files |

Hosted CI runs before freeze: `build` refuses until `ci` has recorded the
passed run of the release commit, so a CI failure is fixed in a new release
commit before any build number is consumed, and the receipt never needs a
separate test-only commit. After `verify-remote` the driver registers the build
in `~/.cfm-release-tooling/releases/shipped.json`, the ledger from which the
next release carries the approved component decisions forward; a release that
shipped before the driver is registered once with
`scripts/cfm_release.sh shipped --add VERSION BUILD ARTIFACT REVIEW`. The
sections below describe what each stage's entry point does and stay the
reference for its recovery rules.

Run the sequence below from one clean release commit. Its `CHANGELOG.md`
heading for the product version reads `## <version> — <freeze date>`: the
publication set ships the frozen file as `MODIFICATIONS.md`, so the date
cannot change after candidate freeze. Source, CI, preflight, or
evidence failures before candidate freeze use their own append-only attempt or
run identity and do not allocate another application build. A failed builder
retains its preflight inputs and partial products and reports their path; only
its temporary Cargo runtime is cleaned up. Before another pre-freeze attempt,
confirm that no freeze intent or signing mutation exists, then preserve the
old preflight tree under a unique private history path. The builder refuses to
overwrite an existing preflight root. Once
`candidate-freeze/intent.json` exists, recovery may only continue an exact
supported transaction of the active GA build without changing application or nested-code
signature bytes. A transaction in the explicit post-receipt
`verification_blocked` state may reopen and verify only its complete exact
private work and receipt; it must not invoke the signing helper or receipt
creator again. A failed or ambiguous signing mutation that lacks that complete
recoverable exact output retires the candidate. A changed application,
entitlement, profile, or nested-code input is a new product lineage, not an
evidence retry.

Before a post-sign failure becomes durable, one non-resume transaction may
replace a poisoned updater verifier session exactly once when the verifier
reports a typed, allowlisted operational failure. The helper must already have
returned exact integer success; the retry budget is spent before the old
session closes; and the fresh session replays the complete public possession
proof against the same frozen root. This never reruns the signing helper,
attempt creation, or receipt creator. Cleanup failure, fresh-session startup
failure, semantic mismatch, or any subsequent operational failure terminates
the attempt and cannot enter `verification_blocked`.

The install and service transactions admit only an application they observe
on the release Mac as an exact supported predecessor, verified by product
version, build number and signed-tree identity. Every supported predecessor
speaks the current engine v6 / Authority v1.1 service vocabulary, which is the
only vocabulary the transactions issue or accept in a journal. Nothing is
declared in advance, and an unsupported or misidentified installation is
rejected before any service mutation. The installed-40019 compatibility
vocabulary and its Authority recovery intent were removed on 2026-10-10 with
the 0.4.0 predecessor profiles; a journal or marker in that form is rejected,
never adopted.

1. run the required source gates and start the three jobs in the `CI` GitHub
   Actions workflow for the exact clean release commit, then wait until that
   run has passed before step 2. The driver's `ci` stage
   (`scripts/run_hosted_ci_preflight.sh`) selects the newest run of the commit
   and verifies it as completely as the receipt will, and `build` refuses until
   it has; a CI failure is therefore fixed in a new release commit before any
   candidate is frozen. Publication preparation and prepackage require the
   successful hosted receipt. Retain the numeric GitHub run ID; no local
   result, older SHA, foreign repository/workflow, or superseded run attempt
   can satisfy the hosted gate;
2. run the fixed builder with the live Developer ID profiles, notary Keychain
   profile, and updater-key custody configured on the release Mac:

   ```bash
   CFW_RELEASE_RUST_TOOLCHAIN=private \
   NOTARY_PROFILE=clashformac-notary \
   MACOS_SIGN_IDENTITY='Developer ID Application: Zi ang Li (YKUPL7Z869)' \
   HOST_PROVISIONING_PROFILE_PATH=/absolute/path/to/host.provisionprofile \
   PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER=379ef639-4fff-4301-b083-3e49578f0910 \
   PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER=3f275eaf-0fca-4af6-97a3-c93c4e83dc15 \
   scripts/build_signed_candidate.sh --ga
   ```

   The builder derives `CFW_BUILD_NUMBER` from `scripts/release_identity.env`
   through the byte-strict loader and exports it to every product build step;
   do not export it. A preset `CFW_BUILD_NUMBER` that differs from the active
   GA build is refused before any candidate directory is created.

   The builder first creates a pre-sign app and native graph, proves current
   updater-key possession against the embedded public key, and freezes the
   complete candidate. Signing then runs in append-only private attempts and
   atomically publishes one `signing-output` container. The notarization
   transaction reopens that transformation before Apple submission and binds
   it through stapling, Gatekeeper, and the final app manifest.

   If signing is already complete but no app-notary attempt has been claimed,
   a tooling-only correction can use
   `scripts/run_notarization_transaction.sh --submit-frozen-candidate` from a
   separate clean executor checkout. Supply `--artifact-repository`, an explicit
   `--toolchain-root`, and the original candidate's source/toolchain arguments
   shown by `--help`. The app path is derived from canonical `signing-output`;
   arbitrary staged apps, existing attempts and repeated submissions are rejected.
   The advisory local notary-readiness check (section 6) runs before claiming
   the attempt or moving signed bytes.
   Toolchain derivation executes the original candidate's isolated verifier,
   not the executor checkout's newer pinned-source policy. Its complete fixed
   digest output must still match the candidate, with no diagnostics admitted.

   The executor's Git/source identity is rederived from shared Git objects,
   checked again before submission, and retained separately at
   `stage-inputs/notarization-executor.json` with the frozen/signing receipt
   identities. This immutable record is provenance, not an Apple success
   receipt. Product source, app bytes, prior receipts, and receipt schemas remain
   unchanged. CI for unrelated executor changes does not replace validation of
   the frozen product inputs.
   An existing app-notary attempt must use its explicit recovery protocol;
   never use this entry to retry an unknown submission or rerun the builder;
3. capture the hosted run through the fixed public GitHub API after freeze.
   One complete successful hosted run for the frozen product commit, or for an
   immutable commit differing only in the reviewed validation/provenance
   adapters and `scripts/tests/`, satisfies ordinary GA's deterministic CI
   requirement. The driver's `ci` stage selects a run of the frozen commit
   itself, and its `receipt` stage refuses a receipt whose tested source is
   another commit. Receipt v5 binds both source identities and the actual hosted
   Xcode version; runtime, dependency-lock and signing inputs must remain equal.
   The reviewed Rust build adapter accepts a hosted selection only for the
   unsigned validation builds 40000 and 50000 (the unsigned preview). GA
   pre-sign builds reject every such override and retain their exact
   production pins. The frozen signed application is not rebuilt.
   It runs the same 26 lane
   commands. A second full local reproduction is optional assurance evidence,
   not a prepackage or corresponding-source prerequisite. The signed product
   still binds its actual build toolchain; installed-app and network acceptance
   remain mandatory. The capture command creates the private `stage-inputs`
   directory and writes `hosted-ci.json`:

   ```bash
   scripts/release_publication_gate.sh --capture-hosted-ci RUN_ID
   ```

   Capture reopens its result. `scripts/release_publication_gate.sh --verify-hosted-ci`
   remains available for independent read-only investigation. Receipt v5 keeps
   the frozen application `source` separate from the real CI `tested_source`.
   Every read compares both complete Git trees, including modes, and rederives
   the tested source identity. Regular-file changes are limited to the existing
   `scripts/tests/` harness and the explicit `CI_VALIDATION_SOURCE_PATHS` set of
   validation, provenance and policy-document adapters. Application/native
   sources, dependency locks and version pins, signing inputs and unclassified
   paths remain byte-identical. The actual tested workflow is re-read from its
   own immutable commit; it is not relabelled as the frozen artifact workflow. The complete
   successful run, all job steps and zero-annotation checks remain mandatory;
   a previous failed run is retained with its actual result. The later capture
   tool's identity remains the separate stage executor identity.

   Each hosted job selects the latest Xcode installed in its runner image,
   deduplicating aliases and ordering marketing version then Apple's numeric
   `CFBundleVersion`. This allows a hosted beta or older image while Apple and
   GitHub release schedules differ. The job verifies and normalizes only that
   application's ownership, records the real version/build, and executes every
   existing build, test and security gate. Unsupported SDK or Swift features
   still fail those actual checks. Receipt v5 retains the selected identity for
   every job. Production entry points reject unsigned-validation selections;
   release packaging continues to require the exact production Xcode pin and
   the consumed candidate's original toolchain provenance.

   Optional local reproduction uses its own explicit journal and produces only
   a local record; it cannot substitute for hosted CI or runtime acceptance:

   ```bash
   scripts/run_sealed_evidence_manifest.sh collect-ci-lanes \
     --artifact-repository "/absolute/operator/target/release-worktrees/$CFW_GA_BUILD" \
     --output "/absolute/operator/target/release-worktrees/$CFW_GA_BUILD/target/candidates/0.5.0/ga/$CFW_GA_BUILD/stage-inputs/local-ci-lanes.json" \
     --journal "/absolute/private/history/local-ci-$CFW_GA_BUILD"
   ```

   Run this entry from the clean operator checkout. The explicit artifact path
   must equal its fixed frozen checkout. The collector records the separate
   executor identity, but runs every lane script and test from the original
   artifact source with its original toolchain. Each invocation retains an
   immutable attempt; `--rerun` selects fresh lane executions without deleting
   previous logs, failures, or toolchain bindings. Only a complete passing
   attempt may create the fixed local lane record. Failed or interrupted
   attempts stay in the journal and are never described as passing. A concrete
   product defect found in any optional check still requires resolution; moving
   the duplicate suite out of the gate does not dismiss its findings.

   Lane subprocesses use the fixed public-file producer `umask 022`; the
   operator's private log or journal permissions do not change test inputs.
   Journal records remain explicitly private. A complete failed attempt can
   be retried with `--rerun`. If a crash leaves an incomplete intent or record,
   preserve that journal, verify its lane processes have stopped, and select
   a fresh explicitly named journal for the same candidate. Do not delete the
   incomplete attempt, interpret it as passing, or allocate a successor build
   merely to obtain a new evidence directory.

   Hosted capture and live verification fix the public repository ID, workflow
   ID/path/name, `pull_request` event, exact tested head SHA, run
   ID/number/attempt, three exact job names, and every successful job step. Each
   job also retains GitHub's `workflow_sha`; it may differ from the tested head,
   but all jobs must agree and the fixed public Contents API must return a
   `ci.yml` at that commit whose decoded bytes equal the clean tested source.
   They read the run both before and after its attempt-specific jobs.
   `prepackage`, final publication, and upload live-revalidate the v5 receipt;
   ordinary sealed-stage verification performs no network access and instead
   reopens the retained workflow projection against the local clean source.
   Notarization follows the same split. `scripts/verify_release_app.sh`
   checks the stapled ticket and Gatekeeper approval live, which needs Apple's
   services, in publication evidence preparation, in `--verify-prepackage`
   (which both packaging commands run), in `--upload-assets`, and once in each
   prepackage and publication seal. A seal makes that check inside its first
   reopen of the prepackage inputs (for prepackage the reopen that composes
   the stage, for publication its reopen of the sealed prepackage stage),
   between the two hashes of the signed app described below. Every other
   reopen of a sealed stage, including the seal's later reopens and its
   confirmation, `verify <stage>`, the GA acceptance seal, the artifact-set
   commands and the GA runtime collector, runs it with
   `--sealed-notarization` instead: the deep code-signature check still runs
   and `Contents/CodeResources` must exist, but stapler and Gatekeeper are
   skipped. That flag is accepted only for the fixed signed app
   `target/candidates/0.5.0/ga/$CFW_GA_BUILD/signed/Clash for Mac.app` in the
   canonical native-content context, and every reopen, live or sealed, hashes
   that app tree, stapled ticket included, against its sealed manifest before
   the check and again after it; a change made and undone entirely between
   those two hashes is not detected. The live check in `--verify-prepackage`
   only gates packaging: the DMG and updater sets each require their packaged
   application's tree to equal the sealed one.
   Build 50029's runtime collection stopped inside such a reopen, most likely
   at its live stapler check during a network outage
   (`docs/release/ga-build-50029-retirement.md`).
   The local 26-lane record remains corroborating toolchain evidence and can
   never replace `hosted-ci.json`;
4. after a signing interruption, inspect the retained attempt through the
   fixed recovery entry:

   ```bash
   NOTARY_PROFILE=clashformac-notary \
     scripts/build_signed_candidate.sh --resume-signing
   ```

   Recovery may reverify complete exact private work only from an explicit
   post-receipt `verification_blocked` state, without rerunning the signing
   helper or receipt creator. It may then publish that exact verified output,
   or confirm a publication whose reply was lost after the `publishing` event.
   During the original non-resume transaction only, the bounded fresh-session
   rule above may absorb one typed operational public-verifier failure after
   helper success. It is not a resume path and never creates new signed bytes.
   A helper failure, an interruption after signing may have started but before
   one complete receipt-bound output was durably recorded, or any other
   ambiguous signing state requires preserving the attempt, retiring the active
   GA build, and allocating a successor. Never create fresh timestamped signature
   bytes under the same frozen build.

   When Apple upload traffic needs the running local proxy, explicitly set
   `CFW_NOTARY_PROXY=http://127.0.0.1:7890`. Only a credential-free loopback HTTP
   endpoint is accepted. The setting supplies proxy environment variables to
   notarytool requests only; it does not change macOS network preferences or
   redirect the compiler, signer or application verifier.

   If an Apple submit reply was lost before its submission ID was persisted,
   recover only with that observed ID:

   ```bash
   NOTARY_PROFILE=clashformac-notary \
     scripts/build_signed_candidate.sh --recover-notarization-id UUID
   ```

   A failed upload with no durable submission observation, submission receipt,
   or recovery intent has a separate explicit recovery option. First reconcile
   the previously observed ID through Apple info/history. If it is unavailable
   or a failed upload has left it In Progress, retain its truthful observation
   and the original unknown attempt and upload the byte-identical retained
   ZIP once, preserving the real command, start/completion times, exit status,
   stdout and stderr. Apple's documented `--no-s3-acceleration` option selects
   its regional S3 endpoint without changing the archive or signing bytes.

   Run the operator's `scripts/run_notarization_transaction.sh` with the existing
   recovery arguments and `--adopt-upload-observation /absolute/private/observation.json`.
   The v2 observation retains its unavailable-ID case. A v3 observation records
   `prior_submission_id`, the actual pending Apple info response and its
   observation time. It ties that ID to the original upload window and rechecks
   the prior status before adoption; Invalid or Rejected requires investigation.
   Both identify the same-archive resubmission and the prior unknown event;
   neither pretends the retry was the original failed upload.
   Admission requires a real successful upload response for the exact retained
   path and new ID. The original four events remain unchanged. Existing bound
   submission IDs cannot be reassigned through this option. Apple must still
   return an Accepted log for the exact archive digest and new upload window,
   followed by normal stapling, Gatekeeper and application verification.
   Import the observation only once; subsequent recovery uses its bound ID
   without the adoption flag and never uploads again.
5. regenerate and legally review the fixed publication source/SBOM closure,
   then seal `prepackage`. Only that immutable stage may authorize DMG and
   updater package creation:

   Run post-freeze stage verification, packaging, installation, journal export and
   runtime acceptance from the clean **operator checkout** containing the
   fixed `target/release-worktrees/$CFW_GA_BUILD` artifact checkout. These operations
   never fall back to treating the operator checkout as artifact source.
   Publication preparation/draft/finalization remain artifact-source operations;
   keep their already reviewed fixed outputs in the frozen checkout. A corrected
   operator verifier reopens those exact outputs without regenerating or
   relabeling the product, signing, notarization or legal-review records.

   Prepackage first reopens the complete notarization transaction and its
   retained pre-staple application. It then recomputes the original signing
   transformation against that exact retained app and the frozen unsigned app,
   including normalization and embedded profiles. The consumed signing-input
   path is never recreated. A receipt without its verified retained input
   cannot authorize the active GA release, and loading a receipt alone does
   not replace this byte-level comparison. No existing receipt is rewritten.

   The shared source adapter checks both clean identities, recomputes the
   operator identity from the artifact repository's shared Git objects, and
   rechecks source stability at publication and installation admission. The
   operator commit is deliberately distinct from the app's frozen commit;
   retain both in the execution record and validate the operator's own CI.
   New stage seals persist the original sealing executor identity separately
   from the candidate source. Their schemas are prepackage v3, acceptance v3,
   and publication v3. A later verifier reopens the original executor from the
   artifact repository's Git history without replacing its identity or the
   seal. Earlier candidate seals remain historical records; they are never
   rewritten into the new schema. Artifact digests and the final upload
   allowlist are unchanged. The source checks detect accidental selection or drift; they do
   not authenticate against the release account. Missing or dirty checkouts
   fail before admission and are never a reason to alter frozen source bytes.
   The independent public-download verifier is different: run it from the
   frozen artifact checkout, because its offline trust anchor intentionally
   requires the exact artifact source identity.

   After successful finalization, retain the complete `publication-prepared`
   intermediate tree in a private history directory outside the reviewable
   workspace, recording and rechecking its byte/mode tree identity. Do not
   discard it or alter the finalized `stage-inputs/publication` directory.
   Downstream verifiers consume that self-contained finalized directory, not
   the preparation tree. Unpacked upstream cryptographic test fixtures are
   legitimate corresponding source but deliberately still match the workspace
   scanner's name-only private-key detection. Their staging lifecycle is not
   a reason to exempt candidate directories or read secret contents in that
   scanner. Pending or failed finalization must retain its preparation inputs
   for explicit recovery rather than claiming a completed publication.

   ```bash
   scripts/release_publication_gate.sh --seal-prepackage
   NOTARY_PROFILE=clashformac-notary scripts/make_dmg.sh
   scripts/make_updater_manifest.sh
   ```
6. while the old CFM is Off and its Host is absent, preserve the inactive
   one-way legacy tombstone and run the fixed maintenance/install sequence:

   CFW need not be running. If both of its known GUI/core processes are
   positively absent, the guard records that absence and preserves the observed
   proxy, DNS, configured routes and tunnel interfaces. Failed or malformed OS
   observations remain blockers. Maintenance runs as the verified owning local
   administrator; it does not obtain its user identity from a required CFW GUI.
   A registered CFM System Extension may remain installed only when macOS
   reports all CFM VPN services Disconnected (or a complete list proves there
   are none). An idle root Packet Tunnel process may remain only in its protected
   OS-managed copy under `/Library/SystemExtensions`, with its exact Developer ID
   signing requirement verified. Host/current-service process absence and the
   signed Authority Off proofs remain required. No VPN activation, registration removal or network-setting command
   is added to the installer.

   ```bash
   scripts/run_archive_install_history.sh --previous-build PREDECESSOR_BUILD
   scripts/run_current_service_transaction.sh --decommission
   scripts/run_dormant_app_install.sh --install
   scripts/run_current_service_transaction.sh --recommission
   scripts/run_ga_acceptance_journal_export.sh --export
   ```

   If only the DNS observation changes after a completed decommission and
   before an installation journal exists, use the explicit continuation:

   ```bash
   scripts/run_current_service_transaction.sh --continue-after-dns-change
   ```

   This command changes no network setting, registration or application. It
   revalidates both exact applications, the unchanged environment, dormant CFM,
   and two matching live CFW observations. CFW processes, binaries, proxy,
   routes and TUN must still match the original teardown; only the DNS digest
   may differ, and the live guard still requires CFW's exact DNS binding.
   A separate immutable record binds the old and new guards to the original
   intent and completed decommission event. It explicitly records a gap; it
   never reports unchanged DNS across that gap or rewrites old events.
   Installation and subsequent service actions each protect the new complete
   guard before and after every mutation. Export retains both guard segments
   and the continuation. Changed identities, other network changes, an already
   started installation, or a second differing continuation remain blockers.

   The history step is needed when the preceding completed installation still
   occupies the fixed producer paths. It validates both terminal journals and
   the exact installed predecessor under the existing maintenance, service and
   install locks. It retains their original bytes beneath
   `/Applications/.com.bill.clashformac.install-history-v1/<previous build>`,
   with a durable intent and completion receipt. A retry resumes the same two renames;
   pending work, contradictory records, changed bytes or unsafe paths block it.
   It neither changes network/service state nor removes an application bundle.

   `--previous-build` names the build whose completed installation journals
   occupy the producer paths. After a completed GA installation that is the
   installed active predecessor, so `PREDECESSOR_BUILD` is the build number of
   the active predecessor described above, and no `--installed-build` is
   given. Both builds the archiver reads must be registry profiles; it rejects
   any other value before touching the journals. `--installed-build` declares
   a newer registered build that replaced the archived one outside the install
   transaction: the archiver then proves that the journals describe the
   archived identity and that exactly the declared tree is installed, records
   that superseding identity in both history receipts, and never describes the
   archived build as the current installation. Without the declaration the
   archiver requires the archived build itself to be installed. The one-time
   retention of the 40072 → 40073 journals is recorded in
   [`ga-build-40073-retirement.md`](docs/release/ga-build-40073-retirement.md).

   Decommission and install each perform their own mandatory admission checks;
   separate `--preflight` calls remain available for diagnosis. The first
   transaction unregisters only ProxyAgent and GlobalAuthority in
   that order, using the signed Host and an append-only event journal. The
   dormant installer then performs the journaled atomic bundle swap, after
   which the installed candidate registers GlobalAuthority before ProxyAgent
   and proves global Off again. Every mutation is bracketed by the unchanged
   CFW process/binary/proxy/DNS/TUN/route guard. Service registration and app
   replacement share one inode-bound outer maintenance lock; the installer
   also requires the exact decommissioned service journal to bind both the
   candidate and the previous application before it can copy or swap bytes.
   Candidate admission invokes `run_release_app_verifier.sh` through its
   privileged-mode Bash entrypoint. That existing wrapper reconstructs the
   closed Python/Apple environment from the fixed artifact checkout; the
   installer does not invoke the lower-level verifier in its minimal process
   environment. Only the shared typed, complete verifier transcript is accepted.
   Candidate toolchain admission likewise runs the frozen source's own isolated
   verifier through the shared candidate-binding adapter, also used by app
   notarization recovery. A newer operator's pin-policy constants never
   reinterpret older artifact pins. The adapter retains the fixed nine-digest
   output, hard process bounds and zero-diagnostics requirement; neither
   consumer may replace a failed live toolchain check with stored metadata.
   After interruption, run only the matching `--recover` entrypoint. This is a
   forward-only release transaction: there is no production rollback command,
   because restoring the old bundle without a matching old-service
   recommission journal would leave an unproven mixed state. Never use
   `launchctl bootout`, `kill`, `sfltool resetbtm`, Finder, `ditto`, or a DMG
   drag as a substitute;
   Only after recommission closes the service journal may the fixed exporter
   read the two producer-owned journals. It first durably records an exact
   source/environment-bound export intent, then atomically publishes the private
   `stage-inputs/ga-acceptance/migration-journals` container. The container owns
   `dormant-install.json`, the complete `service-transaction` tree (including
   its `environment.json`), `export-intent.json`, and `export-receipt.json`.
   Export never edits, moves, or relabels either producer journal, and raw
   machine or APFS UUID values may not enter the container. It requires the
   already-existing private maintenance, service, and install lock files and
   never recreates a missing producer lock. `--verify` reopens only this fixed
   container, holds the `stage-inputs` identity across the complete descendant
   verification, and never consults mutable producer paths.

   If export reports `recovery required` or an outcome-unknown interruption,
   retain every source, pending path, and intent, then run only the fixed
   recovery flow:

   ```bash
   scripts/run_ga_acceptance_journal_export.sh --recover
   scripts/run_ga_acceptance_journal_export.sh --verify
   ```

   `--recover` is not a normal post-export step. It may complete only the exact
   durable intent against byte-identical source journals and the same fixed GA
   environment; it must not overwrite an already published container;
7. after the atomic journal export verifies, run the fixed GA runtime collector.
   It independently reopens the DMG set, proves the DMG's
   contained app equals the installed active GA tree, derives all twelve required
   checks from bounded command output and packet captures, and proves shutdown
   restored the CFW guard. Before any command, `collection-intent-v4` stores a
   fresh complete CFW baseline, binds the closed installation/service journals
   and records the operator checkout and release Python (path and version)
   running the collection. The closed launcher admits that Python before
   collection starts. Historical journal closure remains required; CFW may
   have restarted or legitimately updated between that history and this
   collection. Every observation within this collection must match its own
   durable baseline. Its first step, the Gatekeeper assessment of the DMG, is
   the only check in `collect` that may consult Apple's services. It runs
   before the app is launched, so a network outage there ends the attempt
   before its mutation boundary, which `recover` only archives.

   Before `collect` records anything, and again right before it launches the
   app, it refuses to start while any Clash for Mac Host runs (a copy opened
   from the DMG included), while a Clash for Mac VPN is not proven
   disconnected (an extension of another team's also refuses), or while macOS
   points an HTTP, HTTPS or SOCKS system proxy at a loopback host in the
   global, a per-interface or a supplemental proxy dictionary. An observation
   that nests a dictionary anywhere else, or any container in an array other
   than the supplemental list, is refused as malformed, here and in
   `recover`. An orphaned Clash for Mac System Proxy or another local proxy
   tool would otherwise fail the collection only at its end, after the
   product restores the system proxy. The refusal names each such proxy. Open
   the installed active GA Clash for Mac, turn System Proxy off in its
   dashboard and approve the macOS prompt, then quit it with Quit Clash for
   Mac (⌘Q) in its app menu, or quit the other proxy tool, and run `collect`
   again. A refusal before anything is recorded needs no `recover`; the
   refusal right before launch leaves an `aborted_before_mutation` attempt
   that `recover` archives first. A proxy on any other host passes. While
   Clash for Windows runs (its app or its core), its own `127.0.0.1:7890`
   System Proxy is left to the CFW guard, which requires exactly that binding
   and its unchanged restoration; an orphaned Clash for Mac System Proxy with
   the same binding cannot be told apart from it then.

   Right before it launches the app, after the DMG proof, `collect` also
   requires the CFW guard to equal the baseline its intent recorded, judged
   as the restored guard is at the end: a guard that differs is observed
   again once a second for up to 30 seconds. A Clash for Windows restart or
   another tool's change to the system proxy, DNS, routes or utun during the
   DMG proof would otherwise fail the collection only at its end, after the
   launch, and need the full `recover`. A guard that still differs ends the
   attempt with "CFW state changed after the collection baseline, before
   launch"; its note names the guard keys that differ, never their values,
   and it leaves an `aborted_before_mutation` attempt. Undo the change, run
   `recover`, which only archives such an attempt, then `collect` again.

   Packet capture needs administrator authorization to open macOS BPF devices.
   The collector requests and proves it before it records anything, sends
   credentials only through a private input pipe, and runs tcpdump with `-Z`
   to drop back to the release account after opening the device. Each capture
   is bounded by its exact test filter, a 32-packet cap and the exercise
   timeout, and is stopped by time (see the capture rules below). An operator
   restoring a live CFM session must complete this authorization before
   stopping that session. Start `collect` from an interactive terminal. There
   it always asks for the administrator password, even while sudo holds a
   cached ticket, and proves that password with `sudo -k` before it records
   anything: a ticket can expire during the DMG proof and the operator waits
   before the first capture. Without a terminal it reads no password; only an
   authorization sudo already holds admits the capture, and otherwise it
   refuses. That refusal, a mistyped password and an interrupt at the
   password prompt all come before `collect` publishes its collection intent,
   so they record nothing and need no `recover`: start a fresh `collect` from
   a real terminal.

   Stages may have different executors. The frozen candidate commit seals
   `prepackage`. Runtime collection, GA acceptance and publication may run
   from a newer clean operator commit that changes only release tooling,
   checked out in place in the same operator directory, while
   `target/release-worktrees/$CFW_GA_BUILD` stays at the frozen commit. Each
   new seal records its own executor, and later verifiers still reopen
   `prepackage` under the frozen commit. Runtime receipts that name the
   operator checkout or the release Python are checked against the collection
   intent's record of both, not against the verifier's own checkout or
   interpreter, so updating the operator commit or the release Python
   (including a Python pin change) between collection and the final upload
   allowlist does not invalidate collected evidence. Moving or re-cloning the
   operator checkout still does: the artifact checkout lives at
   `<operator>/target/release-worktrees/$CFW_GA_BUILD`, the DMG verifier
   receipt's own arguments name its absolute path, and verification compares
   them with the current artifact path. That checkout is also a Git worktree
   registered with the operator checkout by absolute path (see
   [Release-worktree preparation](#release-worktree-preparation)).
   Do not move or re-clone the operator checkout in that window.

   The DNS check observes the product's tunnel leg on the Packet Tunnel
   `utun`, which tcpdump opens as `link-type RAW (Raw IP)`. The Packet Tunnel
   gives macOS two DNS peers, and macOS lists the IPv6 peer first: the system
   resolver normally sends the sender's `getaddrinfo` A query from the tunnel
   client `2001:2:0:64::1` to the tunnel DNS peer `2001:2:0:64::2`, and
   otherwise from `198.18.64.1` to `198.18.64.2`. The evidence resolver
   answers only evidence-token names under `evidence.test`, so other system
   lookups go unanswered during the check and macOS may move a later lookup
   to the other peer. Each stage's token transaction may therefore use either
   tunnel leg, and different stages may use different legs; the evidence
   records the leg family of each stage. A stage's query and its answer must
   use the same leg with the reversed addresses and ports. A stage may repeat
   its query, on either leg, from any client port and under any DNS ID, and
   libbox relays an answer to each one it receives: libbox forwards the query
   outside the tunnel to the evidence resolver and relays that resolver's
   `192.0.2.1` answer, which echoes the client's RD bit. Every query of a
   token must be the same exact A query, and every answer the same exact
   authoritative answer, byte for byte after the DNS ID. Each answer must
   answer an earlier query of its token on the same leg, client port and ID.
   An orphan answer, an answer before or at its query's time, a non-exact or
   conflicting answer, a non-A query for a token name, a message in the wrong
   direction on its leg, or any record of another name or off both legs fails
   the check. Each token needs at least one answered query; a query left
   unanswered, as when macOS asks the other peer again, is allowed. Its first
   matched pair, the earliest answer and the first query it answers, is the
   stage's event for the marker windows and the response digest, and the
   evidence records that pair's leg family. A stage's repeats may arrive
   after its sender returned, even during a later stage or the settle, and
   are judged with the rest; none may precede its own sender or follow the
   capture's end. The capture filter admits only DNS between the two
   addresses of either leg whose first name label has a token's length, stage
   prefix and first eight digest characters for this collection, so other
   system DNS and another collection's tokens cannot reach it. On the IPv6 leg
   it requires UDP as the next header and reads that label at a fixed offset
   behind the 40-byte IPv6 header, so a query behind an IPv6 extension header
   is not captured and its stage fails closed. The filter does not check the
   query type or the rest of the name: a non-A query for a token name is
   captured and fails validation, which needs `recover` and a fresh
   `collect`. Every traffic capture runs with a 262144-byte snapshot length,
   the most the evidence parser accepts; tcpdump's default on the utun is
   larger.

   The TCP and UDP checks send each stage's token once, on the stage's own
   connection or socket. TCP admits a repeat of a stage's data segment only
   when it is an identical retransmission: the same flow and sequence number,
   with the token as its whole payload; any other segment fails. No
   retransmission rule is defined for UDP, so UDP still requires exactly three
   datagrams.

   Each capture is stopped by time. tcpdump runs with `--immediate-mode` and
   writes its pcap into an unlinked private file. 1.5 seconds after the end
   marker's sender returns, the collector lists the process group that the
   capture's sudo leads (`ps -x -g <sudo pid> -o
   pid=,ppid=,ruid=,uid=,svuid=,state=,ucomm=`) and finds the one process
   named `tcpdump` (by its accounting name) that sudo runs, as its child or in
   its place. The settle starts only while at least 2 seconds of the
   35-second exercise will remain after it, one each for that listing and for
   tcpdump's statistics and exit; otherwise the capture fails before the
   settle with "packet exercise has no time for the capture settle and stop",
   instead of the deadline passing after the settle and tcpdump being killed
   without its statistics. `-Z` must have made that tcpdump's real, effective
   and saved user IDs all the release account's; the collector then sends it
   alone one SIGINT. sudo, which may keep root, is not signalled, and neither
   is the process group: a second SIGINT ends tcpdump on macOS without its
   statistics. If sudo does not run exactly one such tcpdump, the capture
   fails before any signal, and the error notes the rows of sudo's process
   group. A tcpdump that has already exited, as its cap stops it, fails as a
   capture that stopped before the collector stopped it. tcpdump must then
   exit 0 and report `N packets captured` with N below 32 and equal to the
   pcap's records, and `0 packets dropped by kernel`. Collection and
   verification judge these statistics before any packet, so a kernel drop or
   the cap is reported as such. Collection applies the same packet proof as
   verification, so a capture that verification would reject fails while the
   traffic step still holds it, with its bytes and standard error retained as
   diagnostics. The capture argv, these statistics and the accepted packet
   set changed without a new runtime evidence schema version; receipts
   recorded with an earlier argv fail verification.

   If a capture fails with "tcpdump refused the operator's interrupt" or
   "tcpdump capture process group could not be cleaned up", a root sudo or a
   tcpdump that never dropped to the release account may still run. Find it
   with `ps -x -g <sudo pid> -o pid=,ppid=,ruid=,uid=,svuid=,state=,ucomm=`,
   where the sudo pid is the one in the failed capture's note "<check> tcpdump
   ran under sudo pid <pid>; …" (for the cleanup failure it appears under its
   `caused by` line), or the one `ps` shows for the capture's `sudo`, stop it
   with `sudo kill -INT <pid>`, then run `recover` and a fresh `collect`.

   Before collection, the evidence VMs `packet-dns-primary-v040` (DNS
   resolver) and `packet-transport-v040` (TCP/UDP endpoint) must be running
   and reachable from this Mac's current public address. Keep the Mac awake
   and on mains power for the whole collection, for example under
   `caffeinate -i`: the collector's timeouts use a clock that stops while the
   Mac sleeps, but its receipts record wall-clock times, so a step that spans
   a sleep fails its duration check.

   When the collector waits for macOS approval and Tunnel mode, approve the
   System Extension and select Tunnel mode with IPv6 enabled in the installed
   active GA dashboard; the Packet Host baseline accepts only a ready Tunnel
   with IPv6 enabled. The system-extension check requires exactly one
   `com.bill.clashformac.packet-tunnel (0.5.0/$CFW_GA_BUILD)` row in
   `[activated enabled]`. macOS keeps each replaced version listed until the
   next reboot as `[terminated waiting to uninstall on reboot]`, with its
   enabled and active columns empty. Every other row for that bundle must be
   exactly such a row with a lower build than the active GA; a row from
   another team, with either column marked, in any other state, or with a
   malformed version or a build of the active GA or later blocks this stage.
   Use the ordinary TUN controls without legacy Prepare or Confirm:

   ```bash
   scripts/run_ga_runtime_acceptance.sh collect
   scripts/release_publication_gate.sh --seal-ga-acceptance
   ```

   Near the end, after the stop/restore case, `collect` prints one line asking
   you to quit the installed active GA Clash for Mac. Quit it with Quit Clash for
   Mac (⌘Q) in its app menu or Quit in its menu bar menu. Never quit it from
   the Dock, AppleScript or Activity Monitor, and never with the macOS Force
   Quit window (Option-Command-Esc). The product's graceful shutdown, which
   normally stops the runtime and proves it Off before the Host exits, runs from ⌘Q,
   the menu bar Quit and the Settings page's own Quit and Force Quit buttons;
   the collector sends the Host no quit request of its own. `collect` waits up
   to 10 minutes for the Host to exit, then runs the single signed Off proof
   without waiting or retrying. A Host still running after 10 minutes fails
   the collection closed, which needs `recover`. The shutdown evidence
   records the instruction that was issued, not the quit control that was
   used: it proves that the Host exited and that a single independent signed
   Off proof and the exact CFW guard restoration followed, but it does not
   identify which quit control ended the Host. A quit from the Dock,
   AppleScript or Activity Monitor, or a Host crash, ends the Host without
   the graceful shutdown and leaves the Packet Tunnel connected until the next
   launch. GA shutdown evidence covers only the graceful quit controls; how
   that product gap is disclosed is the release owner's decision.

   A successful `collect` includes its own verification. For a separate read-only
   investigation, `scripts/run_ga_runtime_acceptance.sh verify` remains available;
   it is not an extra step after successful collection. If `collect` explicitly
   reports an interrupted runtime boundary, preserve the attempt and run:

   ```bash
   scripts/run_ga_runtime_acceptance.sh recover
   ```

   Recovery performs fixed shutdown/Off/CFW checks, archives that failed
   attempt, and requires a fresh `collect`. If Clash for Windows was running
   when the attempt recorded its baseline, the guard must again equal that
   baseline exactly. Otherwise the baseline digests the whole system, which
   may have changed for reasons of its own since the attempt, so recovery
   requires only that no Clash for Mac network state remains: no interface,
   route or DNS resolver of the Clash for Mac tunnel plan, and a system proxy
   that either equals the baseline byte for byte or enables no HTTP, HTTPS or
   SOCKS proxy on a loopback host; the PAC and WPAD switches, which a
   Tunnel-mode collection does not change, are not compared. Either way it
   observes again once a second for up to 30 seconds; recovery without Clash
   for Windows then names each remnant it still finds. Another tool's loopback
   proxy or tunnel-plan address looks the same, so check before treating one
   as Clash for Mac's. If the installed Host is running,
   it prints the same quit instruction and waits up to 10 minutes for the
   Host to exit. If that wait ends without the exit, the error says what to
   do: quit it with Quit Clash for Mac (⌘Q) and rerun `recover`. If it does
   not exit after ⌘Q, stop and investigate instead of quitting it any other
   way.
   If the Host is already gone, recovery goes straight to the single signed
   Off proof. When that Off proof fails, the Host probably exited without its
   graceful shutdown and left its runtime on, and the error says what to do:
   open Clash for Mac so its startup reconciliation stops the orphaned
   runtime, confirm its dashboard shows TUN Mode and System Proxy off, quit it
   with Quit Clash for Mac (⌘Q) and rerun `recover`. After reconciliation the
   dashboard may show Off or a stopped failure state; do not retry either
   mode. If the Off proof still fails after that, stop and investigate
   instead of repeating these steps. Recovery never relaunches the app and
   never retries the Off proof. It refuses before any runtime
   command while `runtime-evidence` or `runtime-acceptance.json` exists, so it
   cannot orphan published evidence. `collect` refuses on the same two outputs
   before any runtime command. Never recover a successful collection.

   `collect` publishes raw evidence only after shutdown, the signed Off proof,
   the exact CFW restore and the post-restore environment check succeed. The
   restored guard must equal the collection baseline exactly; configd can
   still be applying the restored proxy, DNS and routes when the Off proof
   completes, so a guard that differs is observed again once a second for up
   to 30 seconds before the collection fails. If it
   then reports that raw evidence is published but sealing did not complete,
   or reports an unknown durability outcome while `runtime-evidence` exists,
   keep every tree and run:

   ```bash
   scripts/run_ga_runtime_acceptance.sh resume-seal
   ```

   `resume-seal` runs no runtime command and repeats every seal check. It
   accepts only this collection with every fixed step event, writes a missing
   `raw_published` marker only after durably reopening and revalidating the
   raw tree, writes the adapter only when it is absent, and only durably
   reverifies an identical adapter. Repeating it is safe; a persistent
   failure keeps this stage blocked. Never run `recover` after raw evidence is
   published. Failures print their `caused by` chain, which names the
   underlying error, and for a failed command its exit status and the end of
   each output stream: at most 4 KiB of each, with control characters
   escaped. An output in which any credential pattern matches anywhere is not
   shown at all: its note gives only its size and says it holds
   credential-like material. Every line of a note is indented by two spaces
   under the failure it belongs to, so only the error line and the `caused
   by` lines start at the left margin.

   Each collection event, including the `raw_published` marker, and the
   adapter are written whole and synced under a temporary
   `.publication-file-pending-*` name in `stage-inputs/ga-acceptance`, then
   renamed to their final name, which is never replaced. A power loss, forced
   termination or interrupt therefore leaves either no file or the complete
   file under its final name. A leftover temporary file is read by no command
   and blocks none; leave it in place, since recovery does not archive it.

   Missing System Extension approval, absent traffic, an installed-Host
   rejection that does not occur, an incomplete journal, or any cleanup drift
   blocks this stage. Never replace a failed check with a hand-written
   `passed` summary;
8. the two-clean-OS physical aggregate, three-hour soaks, full adversarial
   matrix, collector HSM receipts, and capability-report graph remain the
   separate assurance extension described in
   [`docs/physical-evidence-v5.md`](./docs/physical-evidence-v5.md). They may
   reference the immutable GA manifest but cannot replace a missing GA gate.
   Missing assurance infrastructure is recorded as incomplete, not as ordinary
   GA failure or fabricated success;
9. once GA acceptance is sealed, close the final publication stage and create
   the distribution set:

   ```bash
   scripts/release_publication_gate.sh --seal-publication
   scripts/release_publication_gate.sh --upload-assets 0.5.0
   ```

   `--seal-publication` reopens prepackage and GA acceptance before sealing the
   distribution set. `--upload-assets` is read-only: it live-revalidates the
   hosted CI receipt, reopens prepackage and checks the frozen app's stapled
   ticket and Gatekeeper approval live, so Apple's services must be reachable
   and Gatekeeper enabled, then reopens the publication stage and all package
   bindings and prints the exact upload allowlist: the bare paths that its
   final artifact-set verification prints last. Every earlier line, including
   the release app verifier's transcript, is a report, not an upload path. It
   does not create a tag, GitHub Release, or upload any file;
10. retain the private signing, notarization, install, runtime, legal-review,
   and raw-evidence roots. Publish only the allowlisted distribution artifacts
   under explicit publication authorization, then perform the independent
   remote-byte verification described below. When the current session already
   contains that authorization, continue without asking for it again. The
   publication seal, exact upload allowlist and remote-byte checks still apply.

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
pinned as `RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256` in
`dependency_pins.env`. Independent updater, distribution, and upload
operations establish their own private verification sessions. Repeated public
possession-proof checks within one operation share the compiled verifier;
updater archive checks likewise reuse their operation's verification producer.
Every replay still reopens the archive, signature, source, dependency, and
toolchain inputs and requires the fresh receipt and build binding to equal the
stored evidence. No successful proof, frozen-candidate result, or stage result
is cached, and no compiled session is passed between processes. Success is
reported only after the session's final input checks and cleanup complete; a
failure after publication retains outcome-unknown semantics. The
packaging verifier requires the authenticated minisign trusted comment to name
that exact versioned archive; an older valid signature cannot be replayed under
a newer manifest version or GitHub release path.

Keep DMG and updater packaging sequential. Their outputs and compiler scratch
directories are separate, but both reopen the same candidate through existing
nonblocking exclusive locks. Concurrent packaging can fail with a lock conflict;
session reuse does not change that coordination contract.

The runtime performs a bounded metadata check against the canonical official
GitHub release identity. From a presented release the user can open the
official DMG release page or, for an installation in `/Applications` that the
user owns, install that release in place. A browser handoff is never reported
as an installation.

In-place installation is one transaction with a fixed order. Before anything
is downloaded the dashboard reviews what an earlier attempt left behind and
reads the registration of both background services through the Host's
read-only `--service-maintenance-v2 status` mode; an installation whose
services could not be unregistered later is refused here, while nothing has
changed. With the core still running, the dashboard then downloads the release
archive within the packaging size bound and keeps it only if the complete
stream matches the embedded minisign key and the signature's trusted comment
names exactly that archive. It extracts the archive into a private staging
directory on the application volume and requires the staged bundle to be this
product, the announced version, a strictly greater `CFBundleVersion`,
compatible with the running macOS, and valid under the release Developer ID
requirement including every nested signature. Nothing outside the staging
directory changes before the user confirms the installation, and the user can
discard the staged release instead. A release whose download failed
authentication is neither installed nor offered through its download page
again until the application is restarted or the published signature changes.

On confirmation the dashboard reads the service registration once more,
opens the installer log, records the hand-off, converges the engine to Off
through the same admitted boundary as quitting (a shutdown error reported with
the engine already Off is recorded and does not keep the application running
with its networking stopped), and starts
`clash-for-mac --finish-update-v1 <transaction>` in its own process group. It
exits only after that installer process holds the update lease, and ends
itself within a bounded time if the window teardown hangs; if the installer is
not admitted in time the dashboard aborts the record and restarts itself
unchanged. The installer process runs no window or renderer code. While it
holds the lease an ordinary dashboard launch is refused. It waits for the
dashboard to exit, requires that no other dashboard process exists (one that
was just refused the lease and is still ending does not count), and verifies
the staged bundle again. It then follows the order of the release-only
`current_service_transaction.py` plus `dormant_app_install.py` sequence by
running the installed Host's own `--service-maintenance-v2` modes as separate
processes: `status`, `unregister-proxy-agent`, `unregister-global-authority`,
`status`. The two unregister modes prove the engine Off natively before they
act; every mode returns a receipt whose postcondition the installer checks.
Only with both services NotRegistered and still no other dashboard process
does it exchange the installed and staged bundles with one atomic rename,
release the lease and start the new application, which registers its own
services from the NotRegistered state like a fresh installation. A start
counts only once a dashboard process other than the one that handed off is
still running two seconds after `open` returned; otherwise it is retried. An
`SMAppService` registration is therefore never carried across a bundle
replacement. See Apple's
[`SMAppService.register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29)
documentation and the corresponding
[Apple DTS guidance](https://developer.apple.com/forums/thread/783539).

Every failure before the exchange leaves the installed application as it was
and ends with the installer starting it again, unless the dashboard that
handed off is still running, which is never opened. A failure in the installer
process is recorded with a stable code in `update-install-v1.json` and
reported by the next dashboard launch, which also removes the staging
directory whatever access its entries give; the installer's own diagnostics
are appended to `update-installer.log` (started over once it exceeds 1 MiB),
and failures in the dashboard, the reviewed outcome of the previous attempt
and one bounded line of the extractor's or `codesign`'s own output are
appended to the `update.json` diagnostic journal. A record file that the
running version cannot interpret or may not use is removed and reported once,
so it cannot block later installations. After a successful
exchange the replaced bundle stays in the staging directory until the new
application has completed native startup; there is no automatic rollback. An
installation that is not in `/Applications`, is not owned by the user, or
cannot be replaced without elevation is refused before any download and keeps
the release page as its only path. No privileged helper, AppleScript or
elevation prompt is involved, and the former Tauri updater runtime is not
linked.

Installed clients are frozen consumers of this contract. Every later release
must stay installable by them: the four-key `latest.json` with exactly the
two Apple Silicon platform aliases, the versioned archive name and GitHub
URL, the release-asset redirect host, the same minisign key, an archive within
the packaging size bound whose only root is `Clash for Mac.app` containing
`Contents/Info.plist` and `Contents/MacOS/clash-for-mac`, at most 50,000
entries and 1 GiB expanded, only files, directories and symbolic links, no
entry that is group- or other-writable or carries a setuid, setgid or sticky
bit, no file with more than one hard link, no symbolic link that is dangling
or resolves outside the bundle (through other links included), directories
their owner can read, write and enter, the product identifier and release
Developer ID, a canonical SemVer greater than every published version, and a
positive decimal `CFBundleVersion` greater than every published build. The
release gate `validate_updater_archive.py` enforces the same rules on every
archive before it is published. A later release must also start correctly
with both services NotRegistered and should resolve an
`update-install-v1.json` record left by its predecessor. Changing any of these
strands the clients already installed.

The ordering and the failure paths of this transaction are unit-tested against
a simulated machine and file-system fixtures. Nothing in that says how a
signed installation behaves: `SMAppService` registration after the exchange,
the maintenance modes started from a running dashboard and from the installer
process, App Management consent, system-extension replacement and the relaunch
must be demonstrated with signed builds on both sides of an update before the
first release that contains it is published.

The updater artifact key embedded in 0.3.5 is not available for 0.5.0 signing.
Consequently, 0.3.5 to 0.5.0 is an explicit manual-DMG migration: publish no
legacy-key, dual-signature, alternate-origin, or unsigned compatibility path.
The 0.5.0 archive and its embedded trust configuration use replacement key ID
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
the active GA build. No updater key, Apple notarization key, local private key, or older
RS256 receipt may substitute for this trust root.

On the provisioned release Mac, invoke updater packaging through its executable
entrypoint. Do not prefix it with `bash`: its `#!/bin/bash -p` boundary prevents
`BASH_ENV`, imported functions, and caller shell options from executing before
the custody checks.

```bash
set +x
scripts/make_updater_manifest.sh
```

The shell entrypoint rejects xtrace, exported shell-option state, startup-hook
variables, dynamic-loader/import/archive environment overrides, and every
current or legacy caller-supplied Tauri secret variable. It resets `PATH`,
resolves one fixed Homebrew Python probe to a canonical interpreter, disables
Python site customization with `-S`, and calls the source-pinned launcher in an
empty, explicit environment with only the archive path.
The launcher verifies the complete fixed Tauri CLI toolchain tree and signer
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
`target/candidates/0.5.0/ga/$CFW_GA_BUILD/packages/updater/vVERSION/`. The DMG, accepted result,
normalized log, private Gatekeeper evidence, submission receipt, and artifact
manifest are sealed and atomically published for release operations as
`target/candidates/0.5.0/ga/$CFW_GA_BUILD/packages/dmg/vVERSION/`. The canonical seals bind exact
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
scripts/release_publication_gate.sh --seal-publication
scripts/release_publication_gate.sh --upload-assets 0.5.0
```

The atomic
`ga/$CFW_GA_BUILD/packages/distribution/vVERSION/distribution-set.seal.json` joins the
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
verification and then reopens and recomputes this final seal. Only the bare
paths it prints last are eligible for upload, not the reports before them such
as the release app verifier's transcript; the earlier signed-app
publication-evidence gate or either component seal alone is not upload
authorization.

The same atomic distribution directory contains one deterministic public
publication bundle, its canonical sidecar manifest, and the standalone public
Gatekeeper projection. The bundle also contains that exact projection together
with the corresponding-source archive and manifest, SPDX and CycloneDX SBOMs,
publication inventory and evidence manifest, machine closure, the project GPL
license, the 0.5.0 changelog as `MODIFICATIONS.md`, and every reviewed
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
./scripts/run_verify_remote_release.sh \
  --version 0.5.0 \
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
