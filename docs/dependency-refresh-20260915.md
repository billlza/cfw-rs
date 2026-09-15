# Compatible dependency refresh — 2026-09-15

The dependency refresh produced 0.4.0 build 40068. Its frozen predecessor 40067 is preserved. The subsequent Tunnel startup correction is allocated as build 40069; installed 40068 and its failed-start evidence remain preserved. This document records source preparation and local validation; it does not assert publication or new-package runtime acceptance.

| Input | Previous | Selected |
| --- | --- | --- |
| `XCODE_VERSION` | 26.6 | 27.0 |
| `XCODE_BUILD_VERSION` | 17F113 | 27A266a |
| `RUST_VERSION` | 1.97.1 | 1.98.1 |
| `GO_VERSION` | 1.26.6 | 1.27.1 |
| `NODE_VERSION` | 24.18.0 | 26.8.2 |
| `NPM_VERSION` | Node-bundled npm | 12.0.2 |
| `PYTHON_VERSION` | 3.14.6 | 3.14.7 |
| `SING_BOX_VERSION` | v1.13.15 | v1.14.1 |
| `GOMOBILE_VERSION` | v0.1.13 | v0.1.13 |
| `GOVULNCHECK_VERSION` | v1.6.0 | v1.6.0 |
| `CARGO_AUDIT_VERSION` | 0.22.2 | 0.22.2 |
| `CARGO_DENY_VERSION` | 0.20.2 | 0.20.2 |
| `TAURI_CLI_VERSION` | 2.11.4 | 2.11.4 |
| `XCODEGEN_VERSION` | 2.46.0 | 2.46.0 |
| `SHELLCHECK_VERSION` | 0.11.0 | 0.11.0 |

## Compatibility changes

- Port all six engine patches onto the exact sing-box 1.14.1 source. Preserve DNS response filtering, bounded fallback, SOCKS lifecycle handling, and credential redaction while adopting the new DNS response actions and libbox interfaces.
- Native interface observations detect a changed IPv4 lease, IPv6 prefix or path cost on the same interface; IPv6 privacy-address rotation alone does not reconnect. The reproduced old failure and new passing tests are retained. A physical phone-hotspot retest is still outstanding.
- Swift packet ownership uses `Synchronization.Mutex`. Swift 6.4 builds use Swift Build output discovery instead of a fixed build-directory layout.
- XcodeGen remains 2.46.0 with a separately pinned dependency patch: Rainbow 4.2.1, Version 2.2.1, XcodeProj 9.16.0 and Yams 6.2.2. Handle host build tools and preserve strict duplicate-YAML-key rejection. The separately pinned AEXML 4.7.0 manifest declares supported watchOS 9.
- npm is an independently sealed distribution. Its exact version and tree are bound into the complete toolchain digest and the UI dependency manifest. Application manifests keep their existing constituent projection.
- Rebuild Tauri CLI 2.11.4 with its checksum-bound compatible lock refresh, including patched rustls. Retain the exact upstream lock identity separately.
- Rust includes official llvm-tools-preview so rust-objcopy can load its matching LLVM runtime. Exact transitive constraints remain where upstream components require them: generic-array 0.14.7 and the compatible toml 0.8.2 / toml_datetime 0.6.3 / toml_edit 0.20.2 cluster.
- Error, warning, info and debug log retention is bounded independently at 200 entries each. Routine traffic cannot evict recent errors. Engine events display their local receipt time; rendering remains capped at 200 visible rows.
- Correct the observed sing 0.9.4 SOCKS UDP address race with a short read/write lock around address state, outside network I/O. Builds use a private source copy with a fixed relative module replacement; the original module cache and materialized engine remain unchanged. The lifecycle patch binds the workspace generator and exact upstream file checksums. Recorded patched go.mod/go.sum identify the materialized seed; the generator deterministically adds the local replacement in the private build copy.
- Scan both the original versioned dependency graph and the corrected build copy. A local Go replacement must not remove the original module version from vulnerability coverage.
- Match the complete reference-client gitlink table to the pinned upstream commit, including the new desktop reference. Keep all reference clients uninitialized.
- Preserve explicit NSError failures while returning Go's required nonnull string zero value for unsupported SSH/SFTP callbacks. Replace two intentional debug-crash pointer conversions with explicit Go panics; debug authorization remains unchanged.
- Release command supervision allows at most 250 ms, within the original command deadline, to observe a reaped process group's disappearance. A denied probe never counts as absence; surviving descendants still fail and are killed, and command exit codes remain unchanged. CI resolves the pinned official Xcode alias before checking the real bundle, retaining exact stable-build, signature, ownership and internal-path checks. Conditional shell guards exit explicitly under macOS Bash 3.2.

## Validation and limits

- Local Swift package: 677 tests across 11 suites; Swift format lint passed.
- Xcode native tests under stable 27.0: 679 Swift Testing cases passed. The four analysis schemes passed without warnings after the callback correction. A compiled callback probe failed on the old implementation and passed on the new one while checking both explicit errors.
- Earlier Rust workspace validation: 766 tests across 29 suites and Clippy with warnings denied.
- Final engine port: 15 Go package groups with race detection.
- Actual local interoperability covered six DNS transports directly and through SOCKS, DNS policy/fallback, HTTP/HTTPS authentication, multihop, automatic selection, ordered fallback, three balancing strategies and userspace WireGuard. The pre-fix run detected the SOCKS UDP race; the corrected run passed with race detection. These fixture listeners do not change the computer's TUN, proxy, DNS or route settings and do not replace physical packet-flow acceptance.
- UI: 135 tests passed after the log-retention correction; the old implementation failed the two new regressions. UI dependency audit reported zero vulnerabilities.
- XcodeGen: release build, 71 upstream XCTest tests and four parameterized cases passed; generated CFM projects match the baseline generator. Source-patch boundary tests passed.
- Source and fail-closed gate contracts: 218 tests passed. Toolchain manifest contracts: 46 tests passed. Candidate/npm identity and CI-lane tests passed.
- Formal preparation produced verified Go, Node, npm, XcodeGen, Go tools, Tauri CLI and libbox artifacts. Complete candidate build and hosted CI outcomes are recorded separately against the checked commit.
- Rust target vulnerability audit: 331 reachable packages, zero advisories; cargo-deny passed. Go vulnerability analysis found no affected packages or reachable symbols; one module-only advisory refers to unused x/crypto/openpgp.
- The GitHub xcode-27 image last checked still contained beta 27A5252f. CI requires stable 27A266a; this requirement is not relaxed.
- Remote packet-evidence binaries and physical collector deployments have not been updated. Their old runtime receipts cannot be relabelled as proof of this source.

## Connection-outage follow-up

The 2026-09-15 14:59 outage remains unassigned. Current CFM HTTPS probes succeeded; a separate direct physical-interface probe through the same configured SOCKS node timed out once after a successful SOCKS handshake. That observation demonstrates an independent upstream-path failure but does not establish the cause of the earlier all-site outage. Older ERROR rows had been evicted by the 200-row mixed log buffer; the retention correction fixes that diagnostic loss for the successor. The ICMP warning alone is not evidence of TCP or UDP failure.

A later live capture recovered 14 complete ERROR rows: ten SOCKS setup deadlines at five seconds and four peer EOFs around three seconds, all through one node ingress across unrelated destinations. The installed engine remained running. A paired probe with longer client waits showed that CFM could complete a request taking 9.3 seconds overall, so the five-second setup deadline is not a blanket HTTP response deadline. No timeout or authentication rule was changed on this evidence.

A subsequent check around 17:00 local time again completed all six paired requests to Google, Apple and GitHub, through the installed CFM and directly through the same physical-interface-bound node. This is evidence of current recovery, not proof that the earlier outage is permanently resolved. The separate UDP race correction has not been established as the cause of those earlier TCP handshake failures.
