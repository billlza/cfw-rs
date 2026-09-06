# macOS release gate

This project releases only an arm64 application for macOS 15 or newer. A green
Rust, JavaScript, or Swift unit-test lane is necessary but does not establish a
releasable Network Extension product.

> **v0.4.0 policy calibration:** the executable ordinary-GA versus assurance
> boundary is recorded in
> [`docs/release/ga-assurance-policy-v040.md`](docs/release/ga-assurance-policy-v040.md).
> The release has one candidate identity: build 40044. Build 40030 is retired
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
> A passing policy or source check alone does not consume build 40044. Its
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
for retiring later candidates. Preserve 40044 while repairing evidence tooling.
The current frozen product-input v1 document includes the complete source
identity; its digest cannot alone distinguish product and evidence changes.
Do not relabel that document or claim that a newer test suite ran at its commit.
An unsupported evidence-only repair remains an explicit evidence failure until
its executor and product-input boundary are implemented and verified; it does
not automatically authorize another build number.

Android and iOS are not release targets. Physical interoperability may use an
iOS device as a test peer, but its harness, device identity, transport capture,
and receipts must be independently source-bound; an Android peer record cannot
be renamed or reused as iOS evidence.
The repository's test-only iOS transport peer remains outside the product and
release bundle. The iPhone Packet-LAN mode now replaces the Android peer as the
active `lan-bypass` evidence source, but no prior pilot or Android receipt is
reusable: every assurance capture requires a fresh dynamic ready address, three
joint Mac/iPhone connection bindings, pcap/Host evidence, and exact cleanup.
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
closure to remove `GO-2026-6179` and `GO-2026-6180`. It also pins
`golang.org/x/crypto v0.56.0` to fix `GO-2026-6354` and `GO-2026-6355`, with
the module's minimum Go version at `1.26.0`; the compiler remains `1.26.6`.
No other selected dependency changed for this SSH correction. The release vulnerability
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
`block`, SOCKS5, Shadowsocks, VMess, VLESS/Reality, Trojan, Hysteria2, AnyTLS, and TUIC
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
- one physical Apple Silicon test Mac with a fixed supported macOS environment
  for ordinary GA; a second clean-OS environment belongs to assurance-only
  qualification.

`verify_release_environment.sh` rejects `.key`, `.pem`, or `.p8` material under
the repository workspace. Git ignore rules are not a key-management boundary:
the active updater key must live in an access-controlled external secret store
or hardware-backed workflow. If a workspace copy may have escaped through a
backup or shared archive, rotate the key and publish an explicit updater trust
migration before release.

## Release-worktree cache scope and recovery

The path/name-only secret-material gate authenticates nested managed caches
against their original `cfm-release-worktree-cache-scope-v1.json` receipts in
the main repository's Git worktree registry. An operating-system device-number
reassignment can make these receipts stale after a reboot even when the
worktree, marker, target and administrative directory retain their inodes.
The gate does not silently renew that authority.

After confirming a device-only reassignment, explicitly recover each affected
live build through the closed production Python boundary:

```bash
./scripts/authorize_release_worktree.sh --recover-after-reboot FIVE_DIGIT_BUILD
./scripts/verify_release_environment.sh
```

Recovery requires the same canonical path, build, detached Git HEAD, reciprocal
registration and all four original inodes. Device remapping must be one-to-one;
directory replacement, filesystem splitting/merging, unsafe metadata and
incomplete original enrollment are rejected. A v1 receipt does not contain a
historical volume UUID, so this is an explicit operator authorization, not proof
that a reboot caused the difference.

The original receipt, worktree and candidates are never rewritten or removed.
A new canonical `cfm-release-worktree-cache-recovery-v1-*.json` record retains
the original and recovered scopes in Git's administrative directory. Readers
look up only the exact current device tuple, never fall back to another record,
and revalidate both receipts before pruning a managed cache. Source files,
candidate trees and unexpected target children remain in the secret scan.

Repeating the same command is idempotent. A complete matching pending file or
interrupted hard-link publication can be resumed under the existing scope
lock, with file and directory durability rechecked. A partial or contradictory
record is preserved and fails closed; it must not be deleted or overwritten to
force success. Further device renumbering requires another explicit recovery.
Cache recovery does not renew a frozen candidate's release evidence, resolve
notarization, consume a build number or establish publication readiness.

Before candidate freeze, a source correction may require a new detached HEAD.
Neither enrollment nor reboot recovery can rebind an existing cache receipt.
After proving that no candidate freeze or external transaction started, retain
the complete failed preparation with `git worktree move` in a new private
history path outside the main workspace. Preserve its source, generated inputs,
attempt logs and original receipt; the receipt remains in the original main
Git administrative directory and does not authorize the moved history path.
Recreate the fixed `target/release-worktrees/40044` path at the verified new
commit, create an empty `target` with mode `0700`, and run
`scripts/authorize_release_worktree.sh 40044` from the main checkout before
copying and revalidating managed dependency inputs. Never edit the old receipt
or copy it into the new registration. Git may name the new administrative
directory `400441`; scope identity comes from the reciprocal worktree path and
receipt, not this suffix. This is another preparation attempt using build
40044, not candidate retirement or a new build allocation.
These reversible checkout, enrollment, input-copy and environment-preflight
steps may run in parallel with hosted CI for the new commit. The signed
candidate builder, candidate freeze and signing must wait until every required
source gate and that exact commit's hosted CI have passed.

## 1. Prepare and seal networked release inputs

Before invoking a closed release entrypoint, separately prepare the fixed Rust
SDK at the effective account's
`~/.cfm-release-tooling/rust-toolchains/1.97.1-aarch64-apple-darwin`.
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
`~/.rustup/toolchains/1.97.1-aarch64-apple-darwin`. Only an unset bootstrap
selection defaults to `global`; the sealed environment always records an
explicit `global` or `private` selection. Neither selection accepts arbitrary
paths or falls back to the other SDK on failure. Both require the same exact
five-component `rustup-component-file-tree-v2` surface and unchanged
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
the exact Rust SDK selected above and Python 3.14.6 Cellar path. The build-40000
unsigned CI entrypoint alone may accept the absolute Python executable emitted
by the SHA-pinned `setup-python` action; it verifies the same exact version and
real executable/runtime identities and includes their content digests in the
toolchain binding. Developer-ID and publication paths reject that selection.
The environment keeps system Git/Bash/Zsh ahead of the owner-only, versioned
policy-tool directory, validates one pinned Xcode Developer tree, and content-binds every
executable used by the CI toolchain identity. Newly executed lane logs remain
in an isolated attempt journal until the ending identity matches the starting
identity; output beyond the fixed 64 MiB streaming limit terminates the
complete lane process group.

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

- `target/candidates/0.4.0/ga/40044/signed/Clash for Mac.app` as the signed binary root;
- `target/candidates/0.4.0/ga/40044/stage-inputs/publication` as the final evidence root.

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
publication_artifact_repository="$PWD/target/release-worktrees/40044"
publication_ga="$publication_artifact_repository/target/candidates/0.4.0/ga/40044"
publication_inputs="$publication_ga/stage-inputs"
publication_libbox="$publication_artifact_repository/target/sources/sing-box-v1.13.15-patched"

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

### Single-GA 40044 release sequence

The canonical allocation ledger is
[`docs/release/build-allocations-v040.json`](docs/release/build-allocations-v040.json).
The build-boundary gate rejects any active validation/final pair or any change
to the immutable retired prefix. Builds 40021 through 40029 retain their
historical retirement records and artifacts; none may be relabelled, rebuilt,
resubmitted, installed, or reused. Build 40030 is retired unbuilt by policy.
Builds 40031, 40032, 40033, 40034, and 40035 are consumed, failed GA
lineages with no canonical signed output or notarization submission. Build
40036 is a consumed, signed, and notarized lineage retired before install.
Build 40037 is a consumed private signed-work lineage retired before canonical
output or notarization.
Build 40038 is a consumed private signed-work lineage retired before a
transformation receipt, canonical output, or notarization.
Build 40039 is a consumed, canonically signed lineage retired because SOCKS5
changes its product inputs. Its original notarization outcome remains unknown
and quarantined, not accepted or failed. Do not resubmit or reuse its bytes.
Build 40040 is a consumed, canonically signed lineage retired before
notarization because fixing the newly reported SSH vulnerabilities changes
its dependency inputs. Its signed bytes and historical CI receipt remain
unchanged and cannot be used as evidence for the corrected candidate.
Build 40041 is a consumed, notarized, packaged and installed lineage retired
before GA runtime acceptance: its legacy cutover preflight attributed the live
Clash for Windows network to the retired installation and could never confirm
the cutover while acceptance required that network to be preserved. Its signed
bytes, notarization, package seals, install journal and aborted collection
remain unchanged. Its completed migration to 40043 is retained as historical
installation evidence.
Build 40042 is a consumed, canonically signed and notarized lineage retired
before packaging or installation because the `release-tooling-tests` lane of
its own frozen source fails under the lane collector's toolchain selection.
Its signed bytes, notarization and hosted receipt remain unchanged and cannot
be used as evidence for the corrected candidate.
Build 40043 completed signing, notarization, both package sets and installation,
then retired for the credential-receipt product defect before GA runtime
collection started. Its signed bytes, original hosted CI, prepackage seal,
package seals and completed 40041→40043 installation journals remain unchanged.
It is the installed predecessor for the guarded 40043→40044 migration; none of
its receipts substitute for the new application's acceptance.
Build 40044 is the sole `active_ga` identity.

Run the sequence below from one clean release commit. Source, CI, preflight, or
evidence failures before candidate freeze use their own append-only attempt or
run identity and do not allocate another application build. A failed builder
retains its preflight inputs and partial products and reports their path; only
its temporary Cargo runtime is cleaned up. Before another pre-freeze attempt,
confirm that no freeze intent or signing mutation exists, then preserve the
old preflight tree under a unique private history path. The builder refuses to
overwrite an existing preflight root. Once
`candidate-freeze/intent.json` exists, recovery may only continue an exact
supported 40044 transaction without changing application or nested-code
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

The install and service transactions bind their service vocabulary to the
application they observe on the release Mac, verified by build number and
exact signed-tree identity: an installed 40041 speaks the current engine v6 /
Authority v1.1 actions, an installed 40019 the compatibility path below.
Nothing is declared in advance, and an unsupported or misidentified
installation is rejected before any service mutation.

The 40019 compatibility path is read-only and exact-version only. Each legacy
unregister action reproves Off before mutation. If a completed Authority
unregister lost its receipt, the transaction first atomically publishes and
fsyncs a lineage-bound current-only recovery intent. It then proves both legacy
processes absent, explicitly registers the current candidate Authority, proves
v1.1 Off, unregisters it again, and records the distinct
`installed_40019_recovery_current_authority_v1_1` profile in the append-only
event. A retry after current registration follows that durable intent instead
of guessing from service status, and it never labels recovery as a legacy v1.0
wire proof.

1. require every source gate and the three jobs in the `CI` GitHub Actions
   workflow to pass for the exact clean release commit. Retain the numeric
   GitHub run ID; no local result, older SHA, foreign repository/workflow, or
   superseded run attempt can satisfy the hosted gate;
2. run the fixed builder with the live Developer ID profiles, notary Keychain
   profile, and updater-key custody configured on the release Mac:

   ```bash
   CFW_RELEASE_RUST_TOOLCHAIN=private \
   CFW_BUILD_NUMBER=40044 \
   NOTARY_PROFILE=clashformac-notary \
   MACOS_SIGN_IDENTITY='Developer ID Application: Zi ang Li (YKUPL7Z869)' \
   HOST_PROVISIONING_PROFILE_PATH=/absolute/path/to/host.provisionprofile \
   PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER=379ef639-4fff-4301-b083-3e49578f0910 \
   PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER=3f275eaf-0fca-4af6-97a3-c93c4e83dc15 \
   scripts/build_signed_candidate.sh --ga
   ```

   The builder first creates a pre-sign app and native graph, proves current
   updater-key possession against the embedded public key, and freezes the
   complete candidate. Signing then runs in append-only private attempts and
   atomically publishes one `signing-output` container. The notarization
   transaction reopens that transformation before Apple submission and binds
   it through stapling, Gatekeeper, and the final app manifest.

   If signing is already complete but no app-notary attempt has been claimed,
   a tooling-only host compatibility correction can use
   `scripts/run_notarization_transaction.sh --submit-frozen-candidate` from a
   separate clean executor checkout. Supply `--artifact-repository`, an explicit
   `--toolchain-root`, and the original candidate's source/toolchain arguments
   shown by `--help`. The app path is derived from canonical `signing-output`;
   arbitrary staged apps, existing attempts and repeated submissions are rejected.
   Local readiness runs before claiming the attempt or moving signed bytes.
   Only individually observed host identities with the exact known finding and
   independent missing-ticket corroboration can use the compatibility branch.
   Toolchain derivation executes the original candidate's isolated verifier,
   not the executor checkout's newer pinned-source policy. Its complete fixed
   digest output must still match the candidate, with no diagnostics admitted.

   The executor's Git/source identity is rederived from shared Git objects,
   checked again before submission, and retained separately at
   `stage-inputs/notarization-executor.json` with the frozen/signing receipt
   identities. This immutable record is provenance, not an Apple success
   receipt. Product source, app bytes, prior receipts, and receipt schemas remain
   unchanged. Executor CI does not replace the original product's exact-SHA CI.
   An existing app-notary attempt must use its explicit recovery protocol;
   never use this entry to retry an unknown submission or rerun the builder;
3. capture the hosted run through the fixed public GitHub API after freeze.
   One complete successful hosted run for the frozen product commit satisfies
   ordinary GA's deterministic CI requirement. It runs the same 27 lane
   commands. A second full local reproduction is optional assurance evidence,
   not a prepackage or corresponding-source prerequisite. The signed product
   still binds its actual build toolchain; installed-app and network acceptance
   remain mandatory. The capture command creates the private `stage-inputs`
   directory and writes `hosted-ci.json`:

   ```bash
   scripts/release_publication_gate.sh --capture-hosted-ci RUN_ID
   scripts/release_publication_gate.sh --verify-hosted-ci
   ```

   Optional local reproduction uses its own explicit journal and produces only
   a local record; it cannot substitute for hosted CI or runtime acceptance:

   ```bash
   scripts/run_sealed_evidence_manifest.sh collect-ci-lanes \
     --artifact-repository /absolute/operator/target/release-worktrees/40044 \
     --output /absolute/operator/target/release-worktrees/40044/target/candidates/0.4.0/ga/40044/stage-inputs/local-ci-lanes.json \
     --journal /absolute/private/history/local-ci-40044
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
   `prepackage`, final publication, and upload live-revalidate the v3 receipt;
   ordinary sealed-stage verification performs no network access and instead
   reopens the retained workflow projection against the local clean source.
   The local 27-lane record remains corroborating toolchain evidence and can
   never replace `hosted-ci.json`;
4. after a signing interruption, inspect the retained attempt through the
   fixed recovery entry:

   ```bash
   CFW_BUILD_NUMBER=40044 NOTARY_PROFILE=clashformac-notary \
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
   ambiguous signing state requires preserving the attempt, retiring build
   40044, and allocating a successor. Never create fresh timestamped signature
   bytes under the same frozen build.

   If an Apple submit reply was lost before its submission ID was persisted,
   recover only with that observed ID:

   ```bash
   CFW_BUILD_NUMBER=40044 NOTARY_PROFILE=clashformac-notary \
     scripts/build_signed_candidate.sh --recover-notarization-id UUID
   ```
5. regenerate and legally review the fixed publication source/SBOM closure,
   then seal `prepackage`. Only that immutable stage may authorize DMG and
   updater package creation:

   Run post-freeze stage verification, packaging, installation, journal export and
   runtime acceptance from the clean **operator checkout** containing the
   fixed `target/release-worktrees/40044` artifact checkout. These operations
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
   from the candidate source. Their schemas are prepackage v2, acceptance v3,
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

   ```bash
   scripts/run_current_service_transaction.sh --preflight
   scripts/run_current_service_transaction.sh --decommission
   scripts/run_dormant_app_install.sh --preflight
   scripts/run_dormant_app_install.sh --install
   scripts/run_current_service_transaction.sh --recommission
   scripts/run_ga_acceptance_journal_export.sh --export
   scripts/run_ga_acceptance_journal_export.sh --verify
   ```

   The first transaction unregisters only ProxyAgent and GlobalAuthority in
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
   contained app equals the installed 40044 tree, derives all twelve required
   checks from bounded command output and packet captures, and proves shutdown
   restored the CFW guard:

   ```bash
   scripts/run_ga_runtime_acceptance.sh collect
   # Only when collect reports that it crossed the runtime boundary:
   scripts/run_ga_runtime_acceptance.sh recover
   scripts/run_ga_runtime_acceptance.sh verify
   scripts/release_publication_gate.sh --seal-ga-acceptance
   ```

   `recover` is not a normal step and must not follow a successful collection.
   Use it only after `collect` explicitly reports an interrupted runtime
   boundary; it performs fixed normal shutdown/Off/CFW checks, archives that
   failed attempt, and requires a fresh `collect`. Missing System Extension
   approval, absent traffic, an installed-Host rejection that does not occur,
   an incomplete journal, or any cleanup drift blocks this stage. Never replace
   a failed check with a hand-written `passed` summary;
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
   scripts/release_publication_gate.sh --upload-assets 0.4.0
   ```

   `--seal-publication` reopens prepackage and GA acceptance before sealing the
   distribution set. `--upload-assets` is read-only: it reopens the publication
   stage and all package bindings, then prints the exact upload allowlist. It
   does not create a tag, GitHub Release, or upload any file;
10. retain the private signing, notarization, install, runtime, legal-review,
   and raw-evidence roots. Publish only the allowlisted distribution artifacts
   after a separate publication authorization, then perform the independent
   remote-byte verification described below.

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
`pinned_build_inputs.json`. Independent updater, distribution, and upload
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

The runtime performs only a bounded metadata check against the canonical
official GitHub release identity and then opens the official DMG release page
for a user-controlled update. It does not download, extract, or atomically swap
the installed app and must not report a browser handoff as installation. After
an external replacement, the `SMAppService` daemon requires an explicit,
verified re-registration transaction before native services resume. That
transaction is deliberately not exposed in-process, so runtime replacement is
absent and no metadata/browser handoff is reported as a completed
installation. The release-only `current_service_transaction.py` plus
`dormant_app_install.py` sequence is the fixed, source-bound maintenance path;
it is not callable from the renderer or updater and does not turn a browser
handoff into installation. The former Tauri updater runtime, in-process archive installer,
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
build 40044. No updater key, Apple notarization key, local private key, or older
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
`target/candidates/0.4.0/ga/40044/packages/updater/vVERSION/`. The DMG, accepted result,
normalized log, private Gatekeeper evidence, submission receipt, and artifact
manifest are sealed and atomically published for release operations as
`target/candidates/0.4.0/ga/40044/packages/dmg/vVERSION/`. The canonical seals bind exact
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
scripts/release_publication_gate.sh --upload-assets 0.4.0
```

The atomic
`ga/40044/packages/distribution/vVERSION/distribution-set.seal.json` joins the
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
./scripts/run_verify_remote_release.sh \
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
