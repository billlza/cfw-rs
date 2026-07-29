# Release supply chain

This document defines the reproducible input and output boundary for the
macOS 15+, Apple Silicon release. A normal Cargo or Tauri build performs no
network download of cores, Go toolchains, libbox, or Xcode products, and Cargo
`build.rs` never invokes Xcode recursively.

## Verified pins

The machine-readable values live in
[`scripts/dependency_pins.env`](../scripts/dependency_pins.env).

| Input | Pin | Verification |
|---|---|---|
| Rust | `1.97.1` | `rust-toolchain.toml` and `rustc --version` |
| Node.js | `24.18.0` LTS | official darwin-arm64 archive SHA-256 |
| Go | `1.26.5` | official darwin-arm64 archive SHA-256 |
| XcodeGen | `2.46.0` (`8445e778451c7e44237b90281bde622d764b0084`) | official source and `Package.resolved` SHA-256 values, digest-pinned installed-resource patch, isolated resolved-only SwiftPM build, resource-generation probe, temporary-path rejection, and complete installed-tree manifest |
| Tauri CLI | `2.11.4` | official crate SHA-256, published and patched lock digests, isolated dependency fetch, offline locked install, and complete clean-payload manifest |
| gomobile/gobind | `v0.1.13` (`9f03b8f25789099c5c8abef4a02085da783ba923`) | embedded Go module identity, module checksum, source tag commit, patched sing-box module graph, and source helper-install pins |
| govulncheck | `v1.6.0` | embedded Go module identity and module checksum |
| cargo-deny | `0.20.2` | Rust `1.97.1` locked source install, version identity, and target-aware policy run |
| sing-box/libbox | `v1.13.14`, `25a600db24f7680ad9806ce5427bd0ab8afe1114` | clean Git checkout plus the repository-owned dependency-security and raw-packet patches, with individual and combined SHA-256 values |
| Apple provider reference | `794eb1741f91765a91f1513e5639296503f072b2` | Git commit identity; reference only |
| deployment | macOS `15.0`, arm64 | Cargo build guard, Tauri config, Xcode settings, artifact inspection |

The pins were verified against the crates.io registry, npm registry, official
Go and Node.js release indexes, and the upstream XcodeGen and SagerNet Git
repositories on 2026-07-26. The gomobile v0.1.13 graph alignment, regenerated
security patch, and source/tool/cache bindings were reviewed on 2026-07-28. The
exact XcodeGen, sing-box, and gomobile tags resolve to their recorded commits. The Apple
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

Network access is isolated to explicit preparation:

1. `scripts/bootstrap_release_toolchain.sh` downloads only the pinned official
   Go and Node.js archives, verifies their SHA-256 digests, and installs the
   pinned SagerNet gomobile, gobind, and govulncheck tools into
   `target/toolchains`. Each completed tree is sealed before its first cached
   execution.
2. `scripts/install_pinned_tauri_cli.sh` builds the checksum-bound Tauri source
   with an isolated Cargo home and target directory. Its sealed payload retains
   only the thin arm64 executable and clean patched crate source (including the
   exact lock and licenses) under `target/toolchains/tauri-cli-2.11.4`; release
   scripts call that exact binary and never resolve `cargo tauri` from an
   ambient Cargo home.
3. `scripts/prepare_ui_dependencies.sh` runs the pinned npm `ci` operation in
   an isolated networked workspace, copies regular files into a self-contained
   tree without npm cache hard links, and seals the complete `node_modules`
   content, modes, and internal relative symlinks against the package-lock and
   verified Node tree. UI builds verify this tree before and after execution.
4. `scripts/materialize_libbox_source.sh` accepts only a clean checkout at the
   pinned commit, clones it locally without hard links, applies the three
   digest-pinned patches in a fixed order, and verifies both the dependency-only
   module diff and the complete source diff.
5. `scripts/prepare_libbox_modules.sh` accepts only that materialized source,
   fills the isolated Go module cache, runs `go mod verify`, and seals the
   completed module-cache tree.
6. `scripts/scan_libbox_vulnerabilities.sh` runs the pinned govulncheck against
   the exact patched macOS package graph and the official Go vulnerability DB.
7. `scripts/build_libbox.sh` sets `GOPROXY=off` and `GOTOOLCHAIN=local`. It
   refuses a different or unexpectedly modified checkout and invokes the pinned
   gomobile binder for `macos/arm64` only.

The original tag's reachable libbox graph was not accepted as-is: the 2026-07-22
symbol scan found reachable advisories in `golang.org/x/crypto`,
`golang.org/x/net`, `golang.org/x/text`, and `google.golang.org/grpc`. The pinned
patch raises those modules, `filippo.io/edwards25519`, and their coupled `x/*`
requirements to the first tested fixed closure. `go mod verify` passes and the
same symbol scan reports zero reachable vulnerabilities. It still reports
`GO-2026-5932` at module scope because `golang.org/x/crypto/openpgp` has no fixed
version; that package is absent from the scanned import graph.

Adding the required `with_clash_api` tag enlarged the scanned import graph. An
earlier 2026-07-26 rescan exposed `GO-2026-5774`, `GO-2026-5775`, and
`GO-2026-5777` in `github.com/go-chi/chi/v5@v5.2.5`; the pinned dependency patch
now raises that router to `v5.3.0`. The current symbol and imported-package scan
reports zero vulnerabilities without an ignore or suppression. The upstream
commit, all three patch byte streams, the combined source diff, and the patched
module files are
independently hashed so a release cannot silently substitute either the tag or
a downstream modification. The raw-packet patch is confined to
`experimental/libbox`: it adds the libbox side of the public
`NEPacketTunnelFlow` datagram-adapter contract without modifying `sing-tun` or
using private Apple APIs.

The offline build command is equivalent to:

```sh
gomobile bind \
  -target macos/arm64 \
  -macosversion 15.0 \
  -libname box \
  -tags-not-macos with_low_memory \
  -tags "$LIBBOX_BUILD_TAGS" \
  ./experimental/libbox
```

The recorded tags match the pinned upstream builder:

```text
with_quic,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0,grpcnotrace
```

`with_low_memory` is the upstream non-macOS-only tag and is not applied to the
macOS slice.

The direct binder invocation adds the explicit `-macosversion 15.0` release
requirement, which the upstream wrapper does not expose. The product tag set is
intentionally smaller than the upstream Apple client: unsupported Naive,
WireGuard, Tailscale, gVisor, and DHCP surfaces are not compiled, so their
transitive archives and warning-prone Cronet payload are absent rather than
suppressed.

`with_clash_api` is not optional. The patched tree sets `needClashAPI` whenever a
platform log writer is installed (`box.go`), and `daemon/instance.go` always
installs one, which is the path our Swift runtime takes through
`LibboxNewCommandServer`. Without the tag, `include/clashapi_stub.go` is compiled
instead of `experimental/clashapi` and its registered constructor fails every
`box.New` call with `clash api is not included in this build`. The tag is also
what makes the application-owned, loopback-bound `experimental.clash_api` block
in the projection (`crates/cfw-singbox-config/src/controller.rs`) reachable.
`scripts/verify_pinned_build_inputs.py` pins the tag list and fails closed if
that block exists without the tag.

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
toolchain identity metadata and matching source license text. Ambiguous
expressions and missing texts remain explicit legal-review blockers.

The current exact closure contains 371 components. The generated blocker report
records 344 automatic license conclusions, 27 components requiring human
license review, 371 copyright attributions requiring human confirmation, and 8
components requiring an explicitly prepared corresponding source root. License
boilerplate is deliberately not misreported as package copyright. The
authoritative machine-readable report is
`target/candidates/0.4.0/review/publication-blockers.json`; these counts must be
regenerated whenever the locked graph changes.

After component review and source preparation, the `prepare`, `draft`, and
`finalize` phases create a versioned SPDX 2.3 SBOM, CycloneDX 1.6 SBOM, reviewed
license set, deterministic complete-source archive, build graphs, native/libbox
manifests, signed-app tree manifest, and an outer evidence manifest. Verification
recomputes all bindings and rejects `NOASSERTION`, missing license text, unknown
binaries, graph drift, source drift, reverse payloads, symlinks or linked files
in evidence, and any post-review tampering.

Production paths are fixed:

- signed app: `target/candidates/0.4.0/signed/Clash for Mac.app`;
- prepared closure: `target/candidates/0.4.0/release/publication-prepared`;
- final evidence: `target/candidates/0.4.0/release/publication`.

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
launcher verifies the exact Tauri tree/signer before reading the one fixed
non-synchronizable Keychain item, holds and revalidates the key/archive/signer
identities, accepts only strengthening deny-only macOS ACLs, and rejects any ACL
grant. Every custody Python process disables site customization; the launcher
itself receives an empty, explicit environment. Release signing injects the
password only into the final pinned signer
environment. Shell tracing, startup hooks, caller secret variables,
repository-local key material, symlinks, hard links, ACL grants, path drift,
and ambient signer-process inheritance are release failures.

The private half of the updater key embedded in 0.3.5 is unavailable. Therefore
0.3.5 cannot authenticate the 0.4.0 archive: the supported transition is a
manual installation from the signed, notarized, stapled 0.4.0 DMG. No second
signature, legacy key fallback, or unsigned compatibility archive is allowed.
The application continues to open the canonical GitHub release page instead of
performing an in-process bundle replacement.

The physical-evidence collector uses a separate trust domain from Apple
notarization and the updater key. Its production policy is source-pinned but
remains `state: not-configured`. A configured policy must bind one complete
Cloud KMS HSM key version using `RSA_SIGN_PSS_3072_SHA256`, the exact DER SPKI
digest, a verified Cloud HSM attestation format/content digest, and approved
collector source/executable digests. Provisioning the KMS key, least-privilege
signer IAM, short-lived workload identity, Data Access audit logging and
retention, certificate-chain/attestation verification, nonce issuance, and the
cross-release replay ledger are external release-operations gates. The
repository creates none of those resources and cannot treat their absence as a
software fallback. See [Physical evidence v4](physical-evidence-v4.md).

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

## Current hard blockers

The source-built libbox adapter, public packet pump, and role-scoped Global
Authority transport are linked into the Packet Tunnel and ProxyAgent product
graph. Their source/unit and unsigned-bundle evidence is not a physical
data-plane verdict: the exact signed and installed candidate must still prove
traffic, performance, cancellation, revocation, crash/reboot recovery, and
fast-user switching on clean physical machines.

The durable Authority journal remains bounded without a crash-safe compaction
protocol, Quarantined has no product repair workflow, and unattended System
Proxy restoration after Authorization Services rights expire has not been
proved. Matching Developer ID profiles now exist for the Host, Proxy Agent, and
Packet Tunnel bundle identifiers, but no exact current candidate has yet
completed signing, notarization, staple, Gatekeeper, or publication evidence.
The module-only, unfixable `GO-2026-5932` boundary also needs explicit release
review. Updater
metadata and its signed artifact contract have project-owned bounds in the
publication script. Runtime revalidates bounded metadata and consumes a one-use
authorization before opening the canonical GitHub release page; it does not
download, extract, or replace the application bundle. Release scripts must
remain fail-closed until the remaining persistence, identity, publication, and
device gates are satisfied;
private KVC access, the old root helper, and downloaded alternate cores are
forbidden fallbacks.
