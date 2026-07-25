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
| gomobile/gobind | `v0.1.12` | embedded Go module identity and source tag commit |
| govulncheck | `v1.6.0` | embedded Go module identity and module checksum |
| sing-box/libbox | `v1.13.14`, `25a600db24f7680ad9806ce5427bd0ab8afe1114` | clean Git checkout plus the repository-owned dependency-security and raw-packet patches, with individual and combined SHA-256 values |
| Apple provider reference | `794eb1741f91765a91f1513e5639296503f072b2` | Git commit identity; reference only |
| deployment | macOS `15.0`, arm64 | Cargo build guard, Tauri config, Xcode settings, artifact inspection |

The pins were verified against the crates.io registry, npm registry, official
Go and Node.js release indexes, and the upstream SagerNet Git repositories on
2026-07-22. The exact sing-box tag resolves to the recorded commit. The Apple
reference commit resolves to upstream `main`; it is not compiled or copied into
the product.

## Networked preparation versus offline build

Network access is isolated to explicit preparation:

1. `scripts/bootstrap_release_toolchain.sh` downloads only the pinned official
   Go and Node.js archives, verifies their SHA-256 digests, and installs the
   pinned SagerNet gomobile and gobind tools into `target/toolchains`.
2. `scripts/materialize_libbox_source.sh` accepts only a clean checkout at the
   pinned commit, clones it locally without hard links, applies the two
   digest-pinned patches in a fixed order, and verifies both the dependency-only
   module diff and the complete source diff.
3. `scripts/prepare_libbox_modules.sh` accepts only that materialized source,
   fills the isolated Go module cache, and runs `go mod verify`.
4. `scripts/scan_libbox_vulnerabilities.sh` runs the pinned govulncheck against
   the exact patched macOS package graph and the official Go vulnerability DB.
5. `scripts/build_libbox.sh` sets `GOPROXY=off` and `GOTOOLCHAIN=local`. It
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

Adding the required `with_clash_api` tag enlarged the scanned import graph, so
the 2026-07-26 rescan additionally reports `GO-2026-5774`, `GO-2026-5775`, and
`GO-2026-5777` in the imported `github.com/go-chi/chi/v5@v5.2.5` router
(`middleware.RealIP` header spoofing, fixed in `v5.3.0`). The scan finds no call
path to them: sing-box's clash API router does not install `RealIP`, and the
controller this product injects binds `127.0.0.1` only with a per-run secret, so
no forwarded-header input reaches that middleware. Raising chi is a source
change to the pinned tree and therefore a new patch with new digests, not a
silent bump. These exact no-call-path boundaries remain release review items
rather than suppressed advisories. The upstream commit, both patch
byte streams, the combined source diff, and the patched module files are
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

`scripts/hash_artifact.py` generates a path-independent SHA-256 tree manifest
for `Libbox.xcframework`. The release evidence must additionally include:

- the complete source commit and source archive hash;
- the original source files, every downstream patch, patched `go.mod` and
  `go.sum`, individual and combined diff digests, and `go mod verify` output;
- Go, gomobile, Xcode, Swift, Rust, Node.js, and npm identities;
- the complete libbox tags and linker flags;
- every XCFramework file digest and the root tree digest;
- arm64 slice inspection output;
- final app, System Extension, Agent, updater, and source archive digests.

A locally present or downloaded XCFramework without this provenance is rejected.

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

The repository does not yet link the source-built libbox adapter into the
Packet Tunnel and ProxyAgent targets. The public packet-pump contract and its
performance gate remain unproven. The system extension's authenticated
global-context configuration, replay, and lease transport is also not linked;
user App Group files and the Data Protection Keychain are forbidden substitutes.
No Developer ID/provisioning/notarization evidence is available in source
control. The module-only, unfixable
`GO-2026-5932` boundary also needs explicit release review. Updater metadata,
compressed bytes, expanded bytes, entry count, entry type, canonical layout,
path conflicts, and symlink containment now have project-owned bounds in both
the publication script and runtime; runtime extraction is descriptor-relative
and no-follow, and commit requires an exclusive engine-Off maintenance barrier.
Release scripts must remain fail-closed until the remaining native, identity,
publication, and device gates are satisfied; private KVC access, the old root
helper, and downloaded alternate cores are forbidden fallbacks.
