# Release supply chain

This document defines the reproducible input and output boundary for the
macOS 15+, Apple Silicon release. A normal Cargo or Tauri build performs no
network download of cores, Go toolchains, libbox, or Xcode products, and Cargo
`build.rs` never invokes Xcode recursively.

## Verified pins

[`scripts/dependency_pins.env`](../scripts/dependency_pins.env) is the
authoritative store of pinned values; this document names pin keys, never their
values. [`scripts/pinned_build_inputs.json`](../scripts/pinned_build_inputs.json)
is the policy those values must satisfy: each key's value format, the tracked
files hashed against their digest pins, the required libbox build tags and their
reasons, and the pin references each release script must keep. The verifier
also fixes the set of pin keys, so a pin cannot vanish from both files.

A few consumers cannot read the pin file and keep a copy that a test or a
release-time check compares with it: `rust-toolchain.toml` and the CI
workflow's Rust and Python versions, the updater signing launcher's fixed Tauri
toolchain metadata, the publication source plans, and the packet-evidence
endpoint's installer and instance identities, which run on or describe the
evidence instances and carry `PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256`.
Otherwise a pinned value appears only in the pin file and in the sources that
consume it (patches, `go.mod` files, lock files).

The evidence tools do not follow the product's `GO_VERSION`. The packet-evidence
endpoint has its own toolchain pins in the table below. The physical collector
is a separate Cloud Run service whose Go identity is its own `go.mod` go
directive and the one digest-pinned `golang` image in its Dockerfile and Cloud
Build, which a release test keeps equal. The independence runs one way: the
endpoint pins live in the pin file, so an endpoint rebinding changes the pin
file's digest, which the CI toolchain binding, the native UI source digest and
the release verifier's inputs record.

| Input | Pin keys | Verification |
|---|---|---|
| Rust | `RUST_VERSION`, `RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256` | `rust-toolchain.toml`, exact six-component `rustup-component-file-tree-v2` surface, and compiler/version identity |
| Node.js | `NODE_VERSION`, `NODE_DARWIN_ARM64_SHA256` | official darwin-arm64 archive SHA-256 |
| Go | `GO_VERSION`, `GO_DARWIN_ARM64_SHA256` | official darwin-arm64 archive SHA-256 |
| Packet-evidence endpoint (evidence tool) | `PACKET_EVIDENCE_ENDPOINT_GO_VERSION`, `PACKET_EVIDENCE_ENDPOINT_GO_DARWIN_ARM64_SHA256`, `PACKET_EVIDENCE_ENDPOINT_BINARY_SHA256` | the pinned-input verifier requires the exact README recipe (its own official darwin-arm64 Go archive SHA-256, a reproducible Linux/amd64 build compared with the binary pin), which an operator runs to rebuild; the installer and instance identities are checked against the binary pin |
| XcodeGen | `XCODEGEN_VERSION`, `XCODEGEN_COMMIT` and the other `XCODEGEN_*` pins | official source and `Package.resolved` SHA-256 values, digest-pinned installed-resource patch, isolated resolved-only SwiftPM build, resource-generation probe, temporary-path rejection, and complete installed-tree manifest |
| Tauri CLI | `TAURI_CLI_VERSION` and the other `TAURI_*` pins | official crate SHA-256, unchanged published lock digest, isolated dependency fetch, offline locked install, and complete clean-payload manifest |
| gomobile/gobind | `GOMOBILE_VERSION`, `GOMOBILE_COMMIT`, `GOMOBILE_MODULE_SUM` | embedded Go module identity, module checksum, source tag commit, patched sing-box module graph, and source helper-install pins |
| govulncheck | `GOVULNCHECK_VERSION`, `GOVULNCHECK_MODULE_SUM` | embedded Go module identity and module checksum |
| cargo-deny | `CARGO_DENY_VERSION` | locked source install with the pinned Rust, version identity, and target-aware policy run |
| sing-box/libbox | `SING_BOX_VERSION`, `SING_BOX_COMMIT` and the other `SING_BOX_*` and `LIBBOX_*` pins | clean Git checkout plus the repository-owned dependency-security, raw-packet, DNS-failover, endpoint-conflict, profile-probe and SOCKS-lifecycle patches, with individual and combined SHA-256 values |
| iPhone Packet LAN peer (test-only) | signed thin-arm64 app tree `identity.artifact.app_tree_sha256` in `scripts/physical_capture/ios_packet_lan_peer_identity.json` | source-tree identity, signed executable/profile/entitlements/certificate pins, dual-hash physical-device selection, CoreDevice receipt validation, and exact install/process/uninstall ownership |
| Apple provider reference | `SING_BOX_APPLE_REFERENCE_COMMIT` | Git commit identity; reference only |
| deployment | `MACOS_DEPLOYMENT_TARGET`, arm64 | Cargo build guard, Tauri config, Xcode settings, artifact inspection |

The pin file holds the active 0.5.0 development values;
frozen 0.4.0 source and candidate receipts retain their original sources and toolchain.
Each signed application's own receipts remain authoritative. Earlier July and August reviews are historical records, not the
current version inventory. The exact XcodeGen, sing-box, and gomobile tags resolve
to their recorded commits. The Apple
reference commit resolves to upstream `main`; it is not compiled or copied into
the product.

Every candidate also carries a repository identity pair: the canonical Git
`HEAD` commit and a SHA-256 closure over all tracked or non-ignored release
inputs under the Rust workspace, Tauri/UI application, native products,
contracts, fixtures, tests, packaging scripts, documentation, and CI policy.
Generated output, dependency caches, local credentials, and ignored workspace
data are never read into that digest. Native product manifests and the app
manifest carry both values; verification recomputes them from the current
checkout. The unsigned validation lane permits a dirty working tree but proves
that its exact release-input digest did not change during the build. A signed
candidate additionally requires a clean repository before the build, after the
application build, and immediately before final artifact sealing, with the same
`HEAD` and source digest at every observation.

## Networked preparation versus offline build

Rust SDK deployment is an explicit prerequisite to consuming the closed release
environment. Release-Mac operations set `CFW_RELEASE_RUST_TOOLCHAIN=private` and
use the effective account's
`~/.cfm-release-tooling/rust-toolchains/$RUST_VERSION-aarch64-apple-darwin`;
`global` preserves the existing CI location under `~/.rustup/toolchains`.
The selector controls deployment independently of the production or unsigned
validation role. Only an unset bootstrap input defaults to `global`; sealed
environments require the explicit selection. Consumers neither provision the
SDK nor fall back between roots.

Both locations must pass the unchanged `rustup-component-file-tree-v2` contract:
Cargo, Clippy, rustc, arm64 standard libraries and rustfmt, their component
manifests, metadata, modes and complete file inventory remain bound to
`RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256`.
Additional components in the user's shared SDK are not silently excluded from
that hash; private selection keeps them outside the selected release SDK.
Frozen 40043 source still admits only its original global launcher layout;
its recorded surface and evidence are preserved rather than rewritten for
the new selector.

Network access is isolated to explicit preparation:

1. `scripts/bootstrap_release_toolchain.sh` downloads only the pinned official
   Go and Node.js archives, verifies their SHA-256 digests, and installs the
   pinned SagerNet gomobile, gobind, and govulncheck tools into
   `target/toolchains`. Each completed tree is sealed before its first cached
   execution.
2. `scripts/install_pinned_tauri_cli.sh` builds the checksum-bound Tauri source
   with an isolated Cargo home and target directory. Its sealed payload retains
   only the thin arm64 executable and clean official crate source (including the
   unchanged published lock and licenses) under `target/toolchains/tauri-cli-$TAURI_CLI_VERSION`; release
   scripts call that exact binary and never resolve `cargo tauri` from an
   ambient Cargo home. Cargo's three root-level runtime tracking/lock files are
   validated and removed only from the private offline cache snapshot before
   each complete registry-tree measurement. The exact normalization contract
   is SHA-256 pinned into both the build-input policy and final toolchain
   manifest; unknown metadata, registry drift, or any fetch/install warning
   fails closed. The compiled Mach-O tree digest is generated evidence for that
   build and is carried into downstream candidate manifests; it is not treated
   as a cross-host source constant because this workflow does not claim a
   byte-reproducible Tauri CLI build across machines.
3. `scripts/prepare_ui_dependencies.sh` runs the pinned npm `ci` operation in
   an isolated networked workspace, copies regular files into a self-contained
   tree without npm cache hard links, and seals the complete `node_modules`
   content, modes, and internal relative symlinks against the package-lock and
   verified Node tree. UI builds verify this tree before and after execution.
4. `scripts/materialize_libbox_source.sh` accepts only a clean checkout at the
   pinned commit, clones it locally without hard links, applies the six
   digest-pinned patches in a fixed order, and verifies both the dependency-only
   module diff and the complete source diff.
5. `scripts/prepare_libbox_modules.sh` accepts only that materialized source,
   fills the isolated Go module cache, runs `go mod verify`, and seals the
   completed module-cache tree.
6. `scripts/scan_libbox_vulnerabilities.sh` runs the pinned govulncheck against
   the exact patched macOS package graph and the official Go vulnerability DB.
7. `scripts/build_libbox.sh` sets `GOPROXY=off`, `GOTOOLCHAIN=local`, and
   `ZERO_AR_DATE=1`. The archive setting removes the wall-clock timestamp from
   Apple's `__.SYMDEF` member, so independent builds from identical inputs are
   byte-for-byte reproducible. The script refuses a different or unexpectedly
   modified checkout and invokes the pinned gomobile binder for the
   `LIBBOX_APPLE_PLATFORM` target only.
8. `scripts/verify_pinned_source_contract.py`, the P0 source gate run by the
   build-script boundary, checks every value in `scripts/dependency_pins.env`
   against the policy in `scripts/pinned_build_inputs.json` without invoking a
   toolchain or requiring generated output; the verification itself lives in
   `scripts/verify_pinned_build_inputs.py`. Every input it reads is opened
   through a repository-rooted, no-follow descriptor chain that rejects
   symlinks, hard links, non-regular files, foreign ownership, group- or
   other-writable modes, and any before/after metadata change.
   The policy repeats no pin value, and it does not re-attest individual
   release scripts. The exact Git commit bound by the
   hosted CI receipt and the candidate freeze's clean-tree `repositoryCommit`
   and release-source digest `releaseSourceSha256` identify every tracked
   release source. Developer ID signing with designated-requirement checks,
   notarization, and the behavioral release tests establish the rest.
9. The active iPhone Packet-LAN adapter independently reopens the source
   identity, signed app tree, executable, profile, minimal entitlements,
   signing certificate and thin-arm64/iOS build metadata before device
   mutation. A fresh CoreDevice list must contain exactly one physical iPhone
   matching both domain-separated device hashes. A dormant wireless list entry
   is only a selection observation: device details must then prove the exact
   connected/prepared state, and fresh lock-state receipts must immediately
   precede the primer and Packet launches. The runtime endpoint is never stored
   statically; it comes from the session-bound ready receipt and is jointly
   checked against the Mac sender, pcap and cleanup evidence.

The original tag's reachable libbox graph was not accepted as-is: the 2026-07-22
symbol scan found reachable advisories in `golang.org/x/crypto`,
`golang.org/x/net`, `golang.org/x/text`, and `google.golang.org/grpc`. The pinned
patch raises those modules, `filippo.io/edwards25519`, and their coupled `x/*`
requirements to the first tested fixed closure. `go mod verify` passes and the
same symbol scan reports zero reachable vulnerabilities. A fresh 2026-08-23
database scan subsequently reported `GO-2026-6179` and `GO-2026-6180` against
the then-pinned `golang.org/x/mod v0.37.0`. Sing-box imports `x/mod/semver`, so
the dependency patch now pins the fixed `x/mod v0.40.0` and the exact coupled
MVS closure: `x/crypto v0.56.0`, `x/net v0.58.0`, `x/sync v0.22.0`,
`x/sys v0.47.0`, `x/term v0.45.0`, `x/text v0.41.0`, and `x/tools v0.49.0`.
The 2026-09-02 SSH advisories `GO-2026-6354` and `GO-2026-6355` prompted the
isolated `x/crypto v0.56.0` update. Its minimum module Go version is `1.26.0`;
the Go `1.26.6` compiler, Rust `1.97.1`, and all other selected dependencies
remain unchanged.
The sealed cache, source tests, and XCFramework were regenerated from this
closure. The current scan reports zero symbol and imported-package
vulnerabilities without an ignore. It still reports `GO-2026-5932` at module
scope because `golang.org/x/crypto/openpgp` has no fixed version; that package
is absent from the scanned import graph.

Two advisories published after the 0.5.0 GA concern the same distrusted
certificate authority intermediates. `GO-2026-6809` (2026-10-21) adds a
`crypto/x509` denylist that `Certificate.Verify` applies; the scanned libbox
graph reaches it, so `GO_VERSION` and the security patch's module Go directive
moved to the fixed compiler release. `RUSTSEC-2026-0382` (2026-10-20) makes
`rustls-webpki` reject those intermediates; the shipped Rust graph moved from
`0.103.15` to `0.103.16`, which changes no other locked package. The released
0.5.0 artifacts keep their recorded inputs.

The v1.13.15 rebase overlap is explicit. The raw-packet and endpoint-conflict patches share no path
with the upstream v1.13.14-to-v1.13.15 change set. The DNS patch shares only
`protocol/tailscale/dns_transport.go`; its rebased hunk preserves upstream's
new HTTP/HTTPS and direct-address parsing and supplies the added empty fallback
tag to both `NewResolveDialer` calls. The dependency patch was regenerated from
the v1.13.15 `go.mod`/`go.sum`, so the upstream sing, sing-tun, sing-quic, and
Cronet selections remain intact while the approved security versions stay
exact.

Adding the required `with_clash_api` tag enlarged the scanned import graph. An
earlier 2026-07-26 rescan exposed `GO-2026-5774`, `GO-2026-5775`, and
`GO-2026-5777` in `github.com/go-chi/chi/v5@v5.2.5`; the pinned dependency patch
now raises that router to `v5.3.0`. The current symbol and imported-package scan
reports zero vulnerabilities without an ignore or suppression. The upstream
commit, all four patch byte streams, the combined source diff, and the patched
module files are
independently hashed so a release cannot silently substitute either the tag or
a downstream modification. The raw-packet patch is confined to the daemon and
`experimental/libbox` integration surfaces: it adds the libbox side of the
public
`NEPacketTunnelFlow` datagram-adapter contract without modifying `sing-tun` or
using private Apple APIs.

The offline build command is equivalent to:

```sh
gomobile bind \
  -target "$LIBBOX_APPLE_PLATFORM" \
  -macosversion "$MACOS_DEPLOYMENT_TARGET" \
  -libname box \
  -tags-not-macos="$LIBBOX_NON_MACOS_TAGS" \
  -tags "$LIBBOX_BUILD_TAGS" \
  ./experimental/libbox
```

`LIBBOX_BUILD_TAGS` enables the pinned upstream transports, including the
WireGuard userspace stack. The `libboxBuildTags` policy in
`scripts/pinned_build_inputs.json` lists every required tag with its reason;
the pinned list must be exactly that set.

WireGuard uses the userspace stack (`system=false`); NetworkExtension remains
the only owner of system tunnel interfaces. The security dependency patch also
repairs the pinned URL-test group's concurrent interface assignments using an
immutable atomic selection snapshot, and preserves an explicitly configured
zero tolerance. It also lets a Reality outbound opt in to the X25519MLKEM768
key share with `support_x25519mlkem768`: upstream strips that share, and
Reality servers since XTLS/REALITY 8cdf7bf refuse a hello without it. The
authentication key still comes from the separate X25519 share, which those
servers use. The patch is checked against the upstream commit and complete
patched source. `scripts/test_advanced_protocols.sh` exercises these paths with
real local protocol peers and the race detector; its Reality target reports
the key exchange each connection negotiated.

`LIBBOX_NON_MACOS_TAGS` holds the upstream non-macOS-only tags; they are not
applied to the macOS slice.

The direct binder invocation adds the explicit `-macosversion` release
requirement from `MACOS_DEPLOYMENT_TARGET`, which the upstream wrapper does not
expose. The product tag set is
intentionally smaller than the upstream Apple client: the unsupported Naive,
Tailscale and DHCP surfaces are not compiled, so their transitive archives and
warning-prone Cronet payload are absent rather than suppressed. WireGuard and
gVisor are compiled (`with_wireguard`, `with_gvisor`) for the userspace
WireGuard endpoint described above.

`with_clash_api` is not optional. The patched tree sets `needClashAPI` whenever a
platform log writer is installed (`box.go`), and `daemon/instance.go` always
installs one, which is the path our Swift runtime takes through
`LibboxNewCommandServer`. Without the tag, `include/clashapi_stub.go` is compiled
instead of `experimental/clashapi` and its registered constructor fails every
`box.New` call with `clash api is not included in this build`. The tag is also
what makes the application-owned, loopback-bound `experimental.clash_api` block
in the projection (`crates/cfw-singbox-config/src/controller.rs`) reachable.
`scripts/verify_pinned_build_inputs.py` requires the pinned tag list to be
exactly the policy's required tags and fails closed if that block exists without
the tag.

The Rust target audit denies warning advisories as well as vulnerabilities.
`RUSTSEC-2026-0386` (informational, unsound) reports that tokio's safe
`AsyncFd` constructors violate I/O safety, so the shipped Rust graph moved from
tokio `1.53.1` to the fixed `1.53.3`, which changes no other locked package.
That release deprecates those constructors; the workspace calls none of them,
so the move adds no warning.

## Artifact identity

`scripts/hash_artifact.py` generates path-independent SHA-256 tree manifests.
Release-managed Go, Node.js, XcodeGen, Tauri, Go-tool, and Go-module trees use the strict
`sha256-tree-v2` contract, which binds the root and every relative member's
content, type, symlink target, and POSIX mode; hard-linked files, missing or
extra metadata, duplicate/unknown JSON fields, and algorithm downgrade are
rejected. A manifest is verified before the corresponding cached binary runs
and again after build use. The release evidence must additionally include:

The source-built XcodeGen payload applies one digest-pinned patch that removes
its source-tree `#file` fallback for `SettingPresets`; the installed
`share/xcodegen/SettingPresets` path is the release layout. Bootstrap verifies
the patch and patched source digests, generates a probe project from that
installed layout, strips debug symbols, and rejects any binary that still
contains its temporary staging root.

- the complete source commit and source archive hash;
- the original source files, every downstream patch, patched `go.mod` and
  `go.sum`, individual and combined diff digests, and `go mod verify` output;
- Go, gomobile, Xcode, Swift, Rust, Node.js, npm, and Tauri identities, plus the
  verified Go/Node/Tauri/tool/module tree digests;
- the complete libbox tags and linker flags;
- every XCFramework file digest and the root tree digest;
- arm64 slice inspection output;
- final app, System Extension, Agent, updater, and source archive digests.

A locally present or downloaded XCFramework without this provenance is rejected.
The libbox manifest records `archiveDeterminism=zeroArDate-v1` as exact metadata;
the verifier requires that binding and rejects missing, changed, or additional
metadata before the XCFramework can be consumed. This turns the deterministic
archive policy into a fail-closed artifact contract rather than an ambient
builder convention.
The signed/unsigned application manifests bind the canonical toolchain identity
and every constituent release tree: Go, Go release tools, Go module cache,
Node.js, the sealed UI dependencies, XcodeGen, and Tauri. The libbox manifest
independently binds its Go inputs. These local manifests detect drift after a
clean bootstrap; they do not turn a same-user-compromised machine into a trusted
builder, so release generation still requires a clean ephemeral runner whose
downloads are observed against the repository pins.

## SBOM and license evidence

The release evidence pipeline is implemented and remains fail closed until its
machine and human inputs are complete. It derives machine-readable inputs from
the exact locked and shipped closure for:

- Cargo packages for the `aarch64-apple-darwin` product graph;
- npm packages actually present in the esbuild metafile, plus the pinned
  darwin-arm64 build packages in the lockfile;
- Go modules linked into the pinned libbox build;
- Swift Package Manager/Xcode dependencies and embedded native frameworks;
- the final app, ProxyAgent, System Extension, updater, and distribution image.

`scripts/build_ui.mjs` writes the normalized esbuild input graph to
`target/ui-build/esbuild-meta.json`. Then
`scripts/prepare_publication_evidence.py review-template` records the complete
component inventory, source-input hashes, package metadata hashes, license-text
hashes, and the evidence method for each automatic license conclusion. An
automatic conclusion is accepted only when it recomputes from both package or
toolchain identity metadata and matching source license text. The same rule
applies to external build tools. A tool that cannot resolve automatically must
carry an explicit `manual-reviewed` / `human-legal-review` conclusion bound to
the exact license files, identity metadata, and rationale; `manual-required`
always blocks. Ambiguous expressions and missing texts therefore remain
explicit legal-review blockers, including the compound klauspost conclusion
and the pinned Xcode EULA.

Hosted CI selects and records the latest Xcode actually available on each
GitHub runner, including a preview when the stable release has not reached the
image. Its explicit unsigned-validation role cannot authorize production
signing or packaging. The production Xcode pin, build-tool license provenance
and frozen application stay unchanged; all CI compile, test and supply-chain
checks remain required. Hosted receipt v5 separately binds the frozen artifact,
the actual tested source/workflow, the reviewed validation-adapter differences
and every job's observed Xcode version/build.

Generating a new template does not invalidate an existing component review.
An approved conclusion may be retained when the component identity, complete
license-file set and bytes, metadata, and corresponding-source scope are
independently rechecked against that approval. Preserve the original review
unchanged, write a separate reviewed copy using the current paths and source
evidence, and record the exact comparison. First-party source updates still
require the current corresponding source to be packaged; they do not by
themselves change an unchanged GPL license conclusion. A new whole-closure
record must bind the new closure digest and component set and distinguish the
retained component decision from the current release authorization. Never copy
an old closure approval onto a different digest, backdate a new review, or
carry a conclusion across changed license terms, component identities, or
source obligations without review.

The generated report records exact component, automatic-license,
human-license-review, corresponding-source, external-tool, and informational
`copyright_noassertion_count` totals. License boilerplate is deliberately not
misreported as package copyright: when no objective component-level attribution
is available, the review template records the exact SPDX 2.3 sentinel
`NOASSERTION`. This is not a license conclusion and is not a blocker. The
authoritative machine-readable report is
`target/candidates/0.4.0/ga/40054/stage-inputs/publication-blockers.json`; these counts must be
regenerated whenever the locked graph changes.

After component review and source preparation, the `prepare`, `draft`, and
`finalize` phases create a versioned SPDX 2.3 SBOM, CycloneDX 1.6 SBOM, reviewed
license set, deterministic complete-source archive, build graphs, native/libbox
manifests, signed-app tree manifest, and an outer evidence manifest. Verification
recomputes all bindings and rejects `NOASSERTION` in license expressions,
unknown SPDX identifiers or exceptions, malformed `LicenseRef` values, missing
license text, unknown binaries, graph drift, source drift, reverse payloads,
symlinks or linked files in evidence, and any post-review tampering. SPDX output
retains component copyright `NOASSERTION`; CycloneDX omits its optional
copyright field for those components.

The expression validator uses a fail-closed reviewed subset of SPDX License
List 3.28.0, pinned to the official list-file digests in code. It admits only
the local `LicenseRef-<idstring>` form required by this release; unbound
`DocumentRef-...:LicenseRef-...` expressions are rejected. `WITH` requires a
reviewed SPDX license on the left and a reviewed exception identifier on the
right.

Production paths are fixed:

- signed app: `target/candidates/0.4.0/ga/40054/signed/Clash for Mac.app`;
- prepared closure: `target/candidates/0.4.0/ga/40054/stage-inputs/publication-prepared`;
- final evidence: `target/candidates/0.4.0/ga/40054/stage-inputs/publication`.

The pipeline never scans `target/release`; historical 0.3.5 signed artifacts,
cores, and helpers cannot be absorbed into 0.4.0 evidence. There is no
environment-variable bypass for this path contract or the publication gate.

The `reverse/` tree is reference-only and must never enter a binary, app, DMG,
updater, publication evidence directory, or corresponding-source archive.

## Release credentials and updater trust

Release credentials are machine-local inputs and never belong in the source
closure. Notarization uses the dedicated, non-synchronizing Keychain profile
`clashformac-notary`, backed by an App Store Connect Team API key with the
Developer role. A candidate may use that profile only after `notarytool`
validates it; credential presence alone is not notarization evidence.

The workspace secret scanner classifies by path and name only and never opens a
candidate. The exact current `AuthKey_DYHRNJ2Z4M.p8` name is the notarization
App Store Connect trust domain; plausible exposure requires revocation/rotation
and reprovisioning `clashformac-notary`. Another canonical
`AuthKey_<10 uppercase alphanumeric>.p8` is an Apple API credential candidate
whose trust domain must be identified before revocation or rotation. Every
other `.p8` remains unknown private material. None of these names defaults to
the updater trust domain.

The 0.4.0 updater artifact trust root is the minisign public key whose key ID is
`233E924581F20ACB`. Its encrypted private key is stored outside every workspace
at `~/Library/Application Support/Clash for Mac Release/Updater/cfw-rs-v2.key`,
with owner-only directory and file permissions and a non-synchronizing
password in the explicit login Keychain under service
`com.bill.clashformac.release.updater`, account `updater-v2`. Updater packaging
must run through the executable `#!/bin/bash -p` entrypoint, never `bash
scripts/make_updater_manifest.sh`. The entrypoint resets caller process state
and invokes a source-pinned Python launcher with only the archive path. That
launcher verifies the complete Tauri tree against its installer-produced
manifest and exact source/toolchain metadata before reading the one fixed
non-synchronizable Keychain item. It binds the fixed signer path, mode, size,
and SHA-256 to the unique verified manifest entry through a held descriptor,
then holds and revalidates the key/archive/signer identities. It accepts only
strengthening deny-only macOS ACLs and rejects any ACL grant. Every custody
Python process disables site customization; the launcher itself receives a
minimal, scrubbed explicit environment. Release signing injects the password
only into the final source-bound signer environment. Shell tracing, startup
hooks, caller secret variables,
repository-local key material, symlinks, hard links, ACL grants, path drift,
and ambient signer-process inheritance are release failures.

The private half of the updater key embedded in 0.3.5 is unavailable. Therefore
0.3.5 cannot authenticate the 0.4.0 archive: the supported transition is a
manual installation from the signed, notarized, stapled 0.4.0 DMG. No second
signature, legacy key fallback, or unsigned compatibility archive is allowed.
From 0.4.0 an installation the user owns in `/Applications` can install a
later release in place. Installed clients accept an archive only if it is
signed with the release key above and contains a bundle signed by the release
Developer ID, so the custody of both and a tested backup of the key are
release-critical. `RELEASE.md` describes the installation transaction and the
contract installed clients depend on.

The physical-evidence collector uses a separate trust domain from Apple
notarization and the updater key. Its production policy is source-pinned and
`state: configured` for the reviewed v0.4.0 Cloud KMS HSM key version, exact DER
SPKI digest, verified Cloud HSM attestation bytes, collector source closure and
immutable OCI image digest. The least-privilege Cloud Run identities,
Firestore replay ledger, Binary Authorization attestation, Data Access audit
sink and locked retention bucket remain external release-operations controls;
repository code neither creates them nor falls back when they are absent. See
[Physical evidence v5](physical-evidence-v5.md) and the
[v0.4.0 collector provisioning record](release/physical-collector-v040.md).

## Release ordering

The release pipeline is strictly ordered:

1. build and hash libbox from the pinned source;
2. build/test/analyze the Xcode native products;
3. build the Tauri application skeleton;
4. embed the Agent, framework, and `.systemextension` in their documented bundle
   locations;
5. sign from the innermost framework/Agent/System Extension outward;
6. verify Team ID, entitlements, provisioning, hardened runtime, secure
   timestamp, arm64 slices, and macOS 15 deployment target at every layer;
7. notarize, staple, validate with Gatekeeper, then create the updater artifact;
8. publish the GPL complete corresponding source, modification notice, license,
   SBOM, and binary/source hash manifest beside the binary.

No later step may repair or replace an input from an earlier step. A failed
identity, signature, entitlement, notarization, staple, source, or runtime gate
blocks release.

## Release and assurance evidence boundaries

The source-built libbox adapter, public packet pump, and role-scoped Global
Authority transport are linked into the Packet Tunnel and ProxyAgent product
graph. Their source/unit and unsigned-bundle evidence is not a physical
data-plane verdict. Ordinary GA requires the exact signed and installed
candidate to prove the traffic, rejection, restoration, and protected-CFW
checks on the single fixed Apple Silicon environment specified in
[the GA policy](release/ga-assurance-policy-v040.md#ga-required-gates).
The wider performance, crash/reboot, fast-user-switching, and multiple-OS
qualification belongs to the separate assurance matrix. Its absence does not
add an ordinary-GA blocker. A concrete correctness or security defect found by
any check still blocks the affected release behavior.

The durable Authority journal remains bounded without a crash-safe compaction
protocol, Quarantined has no product repair workflow beyond releasing a stop
whose owner process provably ended for the Host to prove Off, and unattended
System Proxy restoration after Authorization Services rights expire has not
been proved by source checks alone. These runtime boundaries must be assessed
from the candidate's actual acceptance evidence, not inferred from unit tests.
Signing, notarization, stapling, Gatekeeper, installation, and publication are
separate stages whose status comes from the current candidate's receipts.
The module-only, unfixable `GO-2026-5932` boundary also needs explicit release
review. Updater
metadata and its signed artifact contract have project-owned bounds in the
publication script. Runtime revalidates bounded metadata and consumes a one-use
authorization before opening the canonical GitHub release page or downloading
the release archive, which it authenticates with the embedded release key
before anything parses it. Release scripts must
remain fail-closed until the remaining persistence, identity, publication, and
device gates are satisfied;
private KVC access, the old root helper, and downloaded alternate cores are
forbidden fallbacks.
