# Client parity implementation

The user approved the 2026-09-14 comparison plan against installed 0.4.0 build
40061 (source `7b87b53cc102fc34e2fd259078344fb4c77380c3`). This ledger tracks
implementation and acceptance separately. Installed artifacts and existing
network ownership are preserved while source work proceeds.

| ID | Accepted work | Implementation | Verification |
| --- | --- | --- | --- |
| G01 | Independent local proxy core; explicit full stop | Implemented in source | Component tests passed; installed acceptance pending |
| G02 | Online profile import, update and selection with failure recovery | Implemented in source | Component tests passed; installed acceptance pending |
| G03 | Providers, rule resources, fallback and session-stable balancing | HTTP/inline resources, atomic updates, health checks and three balancing policies implemented; remaining compatibility tracked below | Real local TCP/UDP balancing and failover passed; installed acceptance pending |
| G04 | DNS policies, domain resolvers, bootstrap and recovery | Encrypted bootstrap, system hosts, domain/dataset policies, independent proxy/direct roles and routed DNS implemented | Generated Rust configurations and real DNS/SOCKS flows passed; installed acceptance pending |
| G05 | Real port, log, MTU and controlled LAN settings | Port/log/MTU/LAN settings, CAS storage and online rollback are wired through commands and UI | Real LAN TCP/UDP allow/deny and transaction recovery passed; installed acceptance pending |
| G06 | Measured subscription capacity and bounded UI/probe work | 1024 nodes, independent groups, bounded memberships, paging and indexed updates implemented; final integrated checks in progress | Component load tests passed; installed UI acceptance pending |
| G07 | Required protocol combinations and optional Xray feasibility | HTTP/HTTPS and certificate/SPKI pinning implemented; conditional Xray assessment complete | Actual CONNECT, TLS pin, name/time and credential failure cases passed; installed acceptance pending |
| G08 | Tray controls, global shortcuts and explicit network automation | Configurable global shortcuts and opt-in ordered Wi-Fi/wired/SSID rules implemented | Collision/recovery, manual-stop ordering and network observation tests passed; installed controls acceptance pending |
| G09 | Installed networking and controlled competitor comparison | Pending | Pending |

## First implementation boundary

Local proxy uses the existing ProxyAgent owner and credential lifecycle. It
does not apply System Proxy or start a Packet Tunnel. Its mode is bound into
the configuration identity and native request, and native observations must
distinguish a ready local core from actual System Proxy ownership. Turning off
the final OS integration preserves the local core; the explicit core stop,
application shutdown and maintenance stop still require complete cleanup.

Online configuration work must retain the active runtime while fetching and
validating candidates, serialize commits, preserve credential audience and
configuration identity, and prevent delayed work from undoing a user's stop.
Failure recovery must use the exact prior inputs and a proven ownership state.

## Validation record

Current evidence directory: `target/client-parity-20260914/`. This is a source
milestone, not a new installed release. Build 40061 and the user's active network
have not been replaced or reconfigured by this work.

- `rust-parity-final-v2.log`: 655 Rust unit/integration checks passed across
  engine API, Apple adapter, application, profiles, projection and shell.
- `native-parity-final-v2.log`: 658 Swift tests passed with warnings as errors.
- `ui-parity-final-v3.log`: all 112 UI/contract/render tests passed. The earlier
  70-test selected run remains recorded separately.
- `clippy-parity-final-v4.log`: all affected Rust targets passed with `-D warnings`.
- `build-contracts-final-v3.log`: 11 source/artifact contract tests passed.
  The earlier 13-test build-input selection is separately retained.
- `rust-format-final.log`, `swift-format-final.log`, `diff-check-final.log`:
  changed-source formatting and diff whitespace checks passed.
- `dns-non-address-red.log`: the old rule chain skips the first two resolvers for
  TXT/MX. `dns-main-final-v2.log` validates the corrected source with real local
  TCP DNS, DoH/TLS rejection, mixed HTTP, IP/domain filters, ordered three-server
  retries, cancellation, and SERVFAIL/REFUSED recovery while preserving NXDOMAIN.
  The final run uses generated Rust fixtures, has no skips, and does not create
  a real TUN or change system networking.
- `materialize-fallback-final.log`: clean upstream plus exactly six pinned
  patches passes source verification. URL-test changes were independently
  reproduced and reviewed before inclusion; unreviewed exploration copies are
  not product inputs.
- `advanced-protocols-fallback-final.log`: actual local protocol regression,
  including ordered fallback TCP/UDP, primary failure/recovery, preserved UDP
  association, all-failed rejection, DNS transports, multihop and WireGuard,
  passed with race detection. This does not create a TUN or change OS settings.
- `libbox-source-suite-fallback-final.log`: full pinned Go source/race/vet lane
  passed. This lane generates and requires Rust DNS fixtures; absent fixtures
  cannot silently skip integration tests.
- `libbox-build-v4.log`: macOS/arm64 framework and all artifact metadata verified.
  Artifact: `target/client-parity-20260914/native-v4/Libbox.xcframework`.
  Framework tree SHA256:
  `e2964043c7efd63c873afabffaa42582f1c71da6314454406c2b30c63989e858`.
  Combined source diff SHA256:
  `3cf503cd607f576f05b45164d71d037f78099655f4aded54cb544d09edb80eeb`.

The final integrated counts include the shared rebind fixture, asynchronous
profile reads, fallback import/projection and tray control additions. Focused
retries and the isolated child assertion are not counted a second time.

## Configuration and recovery behavior

Remote input is fetched before queue admission. Preparation, credential binding,
native validation, runtime replacement and catalog commit run in one serialized
coordinator operation. Status polling cannot interleave with native preparation.
An earlier Stop remains Off when a late subscription response arrives. Once an
operation is admitted, losing the UI waiter does not abandon its transaction.

Invalid native configuration leaves the working runtime untouched. A failed
candidate start or catalog commit restores the previous source only after exact
cleanup is proven. Restoration uses a new generation and reports the failed
change; an unproven owner or failed restoration remains an explicit error.
This is a restart-based replacement: existing connections may reconnect.

Manual node selection is read back and saved, including selections made from the
tray. Updates retain choices that still exist and report groups whose chosen node
was removed. Routing/DNS edits can rebind unchanged credential-bearing nodes to
the new profile digest inside the native vault, retaining the old audience.
Changing a credential-bearing node's definition requires importing its updated
credentials; it cannot silently reuse the old secret at a different endpoint.

Profile reads that wait for an online transaction's file lock run outside the
UI/coordinator executor. Editor saves carry the opened document digest and
reject stale edits instead of overwriting a newer subscription or manual edit.

The frontend no longer dispatches a second restart or rollback after a backend
profile transaction. Routine imports, selection, updates, metadata edits and
unselected-profile deletion no longer require the core to be Off. Credential GC
and destructive legacy maintenance retain their own explicit controls. GC is
not an automatic prerequisite for subscription updates.

## DNS coverage and remaining scope

Supported: one to eight numeric or authenticated encrypted bootstrap transports;
domain-named UDP/TCP/DoT/DoH/DoQ/H3 endpoints; independent ordinary, proxy-node
and direct resolver pools; exact, wildcard, suffix, geosite and domain-provider
policies; system hosts; GeoIP/domain/IP fallback filters; and explicit direct,
selected-proxy or routing-rule DNS socket paths. Direct resolvers can apply the
ordinary domain policies, and proxy-node resolvers can have their own policies.

Named DNS chains preserve domain selection and response filtering for connection
lookups. DNS transport endpoint names terminate at numeric bootstrap; routing-rule
DNS requires an explicit proxy-node resolver pool. This breaks the dependency
cycle without changing a routed resolver to DIRECT. TLS verification is retained.
The core route selector handles the real socket and skips inbound DNS hijacking,
sniffing and redundant resolution for that internal, already bootstrapped socket.

GeoIP filtering checks every returned address. Dataset selectors retain source
order; contiguous domain patterns use domain-tree specificity. Provider domain
conditions are stored in one inline rule set and referenced from multiple DNS
policies. Geosite and GeoIP resources use named SagerNet datasets with a persistent
cache and daily updates. Data availability remains a runtime dependency; missing
data is not replaced by an empty successful filter.

The source model still rejects unsupported DNS modifiers explicitly (for example,
arbitrary interface modifiers and automatic `prefer-h3`). This is the accepted
DNS-role and recovery work, not a claim of every Mihomo configuration field.

## Preserved failures and acceptance boundaries

Earlier failed logs remain in the evidence directory. In particular, the copied
Go source included unpinned URL-test edits; the final source was reconstructed
from clean upstream. Initial local build invocations selected an older module
cache or lacked the closed Python entrypoint; corrected invocations use the
task-owned verified toolchain/cache and explicit Python selection. Its module
manifest includes the group test closure; the older historical cache is intact.

A pre-existing flock assertion was vulnerable to the descriptor-inheritance
window of concurrent process creation. The same lock/drop assertions now run in
an isolated test process; no ownership assertion or product cleanup rule was
weakened. Native request protocol 10 and owner/config schema 7 are separate from
old stored-descriptor recovery, which remains tested.

Explicit provider/protocol compatibility limits remain documented. Signing and packaging a complete app,
installation, sustained TUN, sleep/network transitions, video throughput and a
same-host competitor comparison remain G09 acceptance work. Local fixtures,
framework construction and test counts do not establish those results.

## Ordered fallback, UDP destination integrity and tray controls

Fallback is a first-class projected core type. It chooses the first healthy
member in source order, retries only connection establishment within one
15-second/caller deadline, and does not replay application payload or invent a
DIRECT route when all members fail. Recovery returns new connections to the
higher-priority member; established external streams and UDP associations stay
on their original member. Health checks remain bounded to ten concurrent probes
and stop on caller/core cancellation. Continuous idle probing (`lazy: false`) is now represented explicitly. Provider
health watchers receive activity from the actual routed node. This is distinct from lowest-latency URL-test selection.
The reference behavior is documented in the [Mihomo fallback documentation](https://wiki.metacubex.one/config/proxy-groups/fallback/).

`urltest-race-red.log` records unsynchronized TCP/UDP selection publication.
The fix uses one atomic selection snapshot, preserves explicit zero tolerance,
and prevents uint16 tolerance addition from wrapping to prefer a slower node.

`fallback-real-v1.log` reproduced an additional SOCKS UDP race in the pinned
upstream association: Read changes the default destination concurrently with
QUIC Write. `socks-udp-destination-red.log` also proves the functional defect:
a second write switches to an address received in an earlier response.
The product's bounded SOCKS dialer now uses the existing fixed-address packet
adapter for connected UDP writes. No dependency cache was patched or replaced.
`fallback-socks-green-v1.log` and the final real protocol lane cover the fix.

Tray controls call the same serialized core/System Proxy/TUN commands as the
dashboard. Checkmarks require a ready runtime with matching mode, owner,
generation and digest; failed intent is not shown as connected. Routing mode
writes are serialized and read back before success. Automatic groups remain
read-only in the tray, and generated node IDs expire with their menu instance.
Global shortcuts and application-owned SSID/network policies are now implemented as described below. OS-level on-demand while the application is closed remains disabled.

## Completion work after the first source milestone

Evidence directory: `target/client-parity-completion-20260914/`.

Provider resources are materialized in the application: HTTP over authenticated
HTTPS and inline proxy resources, YAML/text domain/IP/classical rule resources,
ordered `use` bindings, bounded regex filters, and app-owned update intervals.
Remote source URLs remain private envelope metadata; changing one participates
in repository conflict detection even though it does not change runtime identity.
Node labels retain their provider names without exposing private source URLs.

Download and aggregate-size limits apply before actor admission. One Update All
operation commits proxy and rule resources together. Retained credential nodes
are rebound inside the native vault, while changed downloaded nodes receive new
references when needed. Invalid downloads or candidates retain the old catalog
and runtime. Identical contents do not restart an already accepted runtime.

Health checks work with an Off core through bounded outbound-only probes, and
with a running core through its authenticated controller. Configured HTTP/HTTPS
URLs, timeouts and expected status ranges survive both paths. Independent
health policies no longer borrow another URL's successful result. Concurrent
checks coalesce; cancelling a waiter does not manufacture an empty success.
The accepted provider behavior follows the [Mihomo provider reference](https://wiki.metacubex.one/config/proxy-providers/).

Load balancing implements consistent destination hashing, ten-minute bounded
sticky sessions and round-robin. TCP streams and UDP associations remain on the
node that established them. The real local fixture records which actual SOCKS
transport received each connection and verifies remote failure and all-failed
behavior. It does not emulate the SOCKS data path or modify OS networking.

Current checks: `subscriptions-split-v3.log` (372 application tests),
`providers-native-v1.log` (658 native component tests, before the new target
codec test), `providers-ui-v3.log` (115 UI tests), `providers-policy-v1.log`,
`providers-core-v1.log`, and `providers-real-v1.log`. The materialized source in
`libbox-groups-pinned` passes the full source/race/vet lane in
`pinned-groups-source-v3.log`. Combined source SHA256:
`be93fccda922c77e2c9f148670699c2c22f1d3463db922cd04d6127a621c2ba3`.
A framework matching this source has not yet been packaged into an app.

Failures from the module split are retained: embedded YAML indentation was
restored byte-for-byte, and unrelated UI actions no longer await a provider
handler before applying immediate cancellation. Existing context-menu helpers
were retained. Provider rendering/operations, subscription transport, parser
regressions and core health execution now have separate modules. Regex filters
compile once per provider/group pass, and retained-node lookup uses an index.
Expanded rule-set references have a total bound before JSON projection.

Not implemented yet: provider downloads through a named route, custom resource
headers, file/MRS resource formats, and arbitrary provider overrides. These are
explicit compatibility failures, not silently ignored input. DNS GeoIP/geosite, system hosts, respect-rules and direct-policy composition
are now implemented and covered by the component evidence below.
No new candidate number, signed app, installation or publication is claimed.


## DNS policy completion and cache correctness

`dns-cache-scope-red.log` reproduces two failures with nonzero TTLs: a direct-role
lookup consumed an ordinary resolver's cached answer, and a warmed answer bypassed
the GeoIP response filter. Resolver caches are now independent in product
configurations; named policies also enforce transport isolation in the core.
Cached responses pass the same current filter as fresh responses. NXDOMAIN and
valid negative answers remain terminal rather than becoming a retry to another
DNS role. Joined errors cannot hide an independent I/O failure.

`dns-policies-integrated-v1.log` passes the actual DNS suite, including the Rust
mixed/TUN/named-policy fixtures, real TCP and UDP through a local SOCKS server,
repeated UDP use after dial cancellation, closed-proxy rejection without DIRECT
fallback, local-host precedence/I/O failure, and cold/warm response filtering.
`dns-bootstrap-real-v1.log` separately validates authenticated encrypted bootstrap
and wrong-certificate rejection. `dns-policy-rust-v3.log` records 85 configuration
unit tests, two integration tests, 374 shell unit tests and eight product-input
checks; these precede the final parser module split. Failure logs remain intact.

`materialize-dns-policies-v1.log` reconstructs clean upstream plus six pinned
patches. `pinned-dns-source-v1.log` passes the complete source/race/vet lane,
including required Rust fixtures and the hosts package. DNS patch SHA256:
`5ce5c4b7cdce7356b64c7f877a030ec088d64b6a065e1d1ce58e555e59dcc003`.
Combined source SHA256:
`39f166cca6ab3afb313326fa2004be2b65a798d351b94619ba56e33f9d9b10b5`.
The new framework build is recorded separately; no installed-app result is
inferred from these checks.

Runtime settings definitions, VMess share conversion and the other URI converters
now have dedicated modules. The collector still owns tag allocation, private
credential references and final validation. File extraction preserves literal
bytes and does not introduce another implementation of credential handling.


`libbox-dns-build-v1.log` builds and verifies the matching macOS/arm64 framework:
`target/client-parity-completion-20260914/native-dns/Libbox.xcframework`, tree SHA256
`0e4eeddab905107f7e5b0d4f85045eaeef498b5cbc45de02fa7e881ffd51d06b`.
`dns-clippy-v2.log` passes all affected Rust targets with warnings as errors.
`dns-and-import-split-final.log` repeats the 85 configuration, two integration,
374 shell and eight product-input checks after the parser/settings module split.
The native component lane is being linked against this framework and the actual
Objective-C platform adapter, so conditional runtime code is compiled as well.
Earlier link setup failures remain recorded and do not count as test passes.


`native-linked-dns-v3.log` passes 667 native tests in 25 suites with warnings as
errors, using the newly built Libbox framework and compiled Objective-C adapter.
The conditional runtime implementation, custom provider health target binding and
mixed retained/new credential provisioning are included. This remains a linked
component test, not a signed installed-app test.

G05 has started: app-owned runtime settings now include log level and an optional
separate LAN listener; port and MTU values reach projection. The LAN listener
requires bounded private-source CIDRs and a deny rule before every route/DNS
hijack; native validation checks that exact boundary while retaining loopback
local/controller endpoints. Default settings preserve existing persisted JSON.
A dedicated canonical runtime preference file uses compare-and-swap revisions.
Online settings transactions, endpoint selection and the visible settings controls
are still pending; this partial source work has not altered installed settings.


## Runtime settings and measured capacity

G05 command/UI transactions are complete in source. Settings saves use the same
serialized runtime replacement and restore path as profile updates. An explicit
port is not silently replaced when occupied. Controller endpoints remain local;
LAN devices use a separate listener and explicit private source ranges. Saving
conflicts preserve the competing writer and restore the prior core with a new
runtime identity. Runtime definitions, General rendering and settings forms are
separate modules. The normal controller snapshot cannot overwrite LAN state from
its unrelated loopback inbound.

`runtime-settings-transaction-v1.log` covers success and a real CAS conflict after
candidate startup. `runtime-settings-lan-real-v1.log` uses the Rust projection and
actual sing-box listeners: allowed TCP/UDP round trips succeed and the forbidden
source fails. This test does not change system networking. `capacity-native-v2.log`
passes 669 native tests with the new framework/Objective-C adapter linked.
Historical 40019 read-only recovery retains its old exact handshake limits.

Capacity is now 1024 remote nodes, 128 groups and 32768 total group memberships,
with a 32-hop dependency bound. The source/profile/runtime byte budgets are
4/2/4 MiB. Credential slots, native frames and repository envelopes are adjusted
at their actual boundaries; per-secret, total-secret and ownership checks remain
independent. The old 128 total-outbound rejection is reproduced in
`subscription-capacity-red-v1.log`. `subscription-capacity-green-v2.log` completes
1024 nodes, 32 groups and 2048 credential slots in about 208 ms in this machine's
debug build (702081 input bytes, 621676 projected bytes). These timings are not
cross-client or installed-app benchmarks.

Proxy presentation lives in `proxies.js`, with 96-node pages, selected-node
navigation and an index for latency updates. Duplicate-name import allocation
and credential lookup use indexes, and graph validation no longer repeatedly
scans every outbound. `capacity-ui-v2.log` passes 120 checks including traversal
of every page and all-node latency updates. Native payload stress and the final
aggregate probe budget are still being checked.

The HTTPS subscription path can now use the exact ready CFM local SOCKS listener.
The pinned reqwest local-DNS SOCKS path resolves through the public-address
validator before sending a numeric CONNECT, preserving TLS hostname validation.
There is no direct retry after a selected-proxy failure. Off/pure-TUN operation
retains ordinary bounded sockets. `subscription-proxy-v1.log` passes 36 subscription
checks including real SOCKS negotiation and private-DNS rejection before a proxy
connection. Named provider routes and arbitrary HTTP headers remain separate
compatibility work rather than implied support.


## Final integrated source verification

The completion directory now includes:

- `parity-final-rust-v1.log`: 754 tests across nine affected Rust packages.
- `parity-final-native-v1.log`: 671 tests in 25 suites, linked to the TLS-capable
  Libbox framework and actual Objective-C adapter, with warnings as errors.
- `parity-final-ui-v3.log`: 125 UI, command-contract, rendering and live-row tests.
- `parity-final-clippy-v2.log`: affected packages and all targets pass `-D warnings`.
- `parity-final-protocols-v1.log`: complete local TCP/UDP, DNS, groups, HTTP/TLS,
  multihop and WireGuard lane passes with race detection and generated Rust inputs.
- `automation-recovery-v1.log`: conflicting shortcuts retain previous bindings;
  successful key rollback cannot disguise uncertain preference persistence.

Native injection of 1024 nodes / 2048 credential slots took about 13 milliseconds
in the observed debug test. Every slot was checked and the source template was
unchanged. This is a component measurement, not installed startup latency.
The browser preview reached page 11 and node 1024 with 64 rendered rows, after
96-row intermediate pages; the settings dialogs scroll to their action buttons.

The main dashboard was reduced from 5507 to 4172 lines while adding capabilities.
General, settings, runtime preferences, automation, providers, proxies, latency
scheduling, rules and connection rendering have explicit module boundaries.
Import URI/VMess/HTTP/TLS handling, DNS policy logic and subscription fetching
were also separated. Existing large evidence/recovery modules were not rewritten
solely to meet an arbitrary line count.

Connection row extraction exposed two existing defects: newly streamed rows had
no Info/Close handlers, and mixing new and existing rows broke sorting. The
incremental reconciler now inserts every row at its requested position and binds
only newly created rows. `connections-reconciliation-red-v1.log` reproduces the
old wrong order; the live-row regression verifies order and one action binding
per button. Controller identity checks remain on close operations.

## Background controls

Shortcuts are optional, require an explicit modifier and reject duplicate keys,
actions and macOS registration conflicts. A serialized owned transaction stages
registrations and atomically saves preferences; bounded compensation restores
old registrations on failure. Uncertain storage or registration recovery leaves
controls blocked with a visible error instead of claiming a successful rollback.

Network automation is off by default and permits up to 16 ordered rules. It uses
physical Wi-Fi/wired observations, two stable samples and a five-second interval.
Named Wi-Fi rules require an actually observed SSID. The application does not
infer an unavailable name or request location at startup; a user-operated button
requests macOS permission. Current-host read-only evidence reported Wi-Fi with
SSID unavailable, so no named-network activation is claimed.

Each observed network edge is consumed once. Automatic requests carry the
engine's current intent revision, including an Off request made while already
Off. A later manual Stop cancels a debounced or queued automatic start. Transient
observation failures do not reset that protection. Rules apply while CFM runs;
this does not enable macOS tunnel on-demand while CFM is closed.

Protocol support and conditional Xray scope are recorded in
[the compatibility assessment](protocol-compatibility-0.4.0.md). Installation,
real network takeover, global-key delivery and sustained comparison are still
separate acceptance work; the records above do not claim those results.


## Candidate preparation

Build 40062 is allocated for the changed application bytes. Build 40061's signed
lineage and install records are preserved. `parity-release-contracts-v2.log`
passes 389 release-input, identity, native graph and source-contract tests;
`parity-build-boundaries-v1.log` passes all build-boundary checks. Eight native
product-input tests also pass for the new identity.

The final framework is `native-tls-v2/Libbox.xcframework` under the completion
evidence directory, with tree SHA256
`88b0a551da69e5ba1cc6bb15548a9b6c4391d5f79f6fc1fd419f855f1849cbcc`.
Its bytes equal the framework used by the 671-test native run. The second build
normalizes the TLS patch to zero-context diff format; it changes the patch's
representation and metadata, not the applied source or framework bytes. The
combined source diff remains
`a04afe84d6156a07df36602d69802222c966585693a57f11bb44a0d25248a604`.

Real browser observations additionally confirm the new connection row order,
Info dialog and Close guard dispatch. The preview was then closed and its
loopback-only HTTP server stopped. These observations use synthetic data and
cannot be substituted for installed native-command acceptance.


A development-directory scan also reported PEM/key filenames inside historical
Go toolchains and module testdata. A flagged Go TLS fixture was byte-identical to
the same fixture in the independently verified Go toolchain. No production key
was read, moved or rotated in response. The candidate uses the existing detached
release-worktree procedure and verified managed dependency roots; historical
development directories are preserved. This is source-scope separation, not an
exception for arbitrary PEM files inside the candidate.


Release regression coverage totals 1020 tests across the two v2 logs. The first
invocation lacked the closed Python/private Rust environment and failed only
related environment assertions. The affected modules then passed unchanged:
16 tests in `parity-release-focused-v2.log` and 46 tests in
`parity-release-toolchain-v3.log`. No assertion or toolchain requirement was
relaxed. All original failed attempts remain available.


`parity-cargo-policy-v1.log` verifies the actual Apple Silicon dependency graph
against current advisory/yanked status, bans, licenses and sources: zero errors,
warnings or notes. Existing dependency versions were not upgraded; the new
global shortcut and Wi-Fi bindings are pinned in the verified Cargo inputs.


The first 40062 preflight stopped before candidate freeze because the tracked
Xcode project omitted newly added shared-protocol files. Regenerating it with
the pinned XcodeGen added the five production/test source references. The
regeneration check passes (`parity-xcode-project-v2.log`). The original clean
source worktree and failed preflight are retained as `source-attempt-1` in the
40062 install history. The unconsumed build number is reused for this correction.


The second preflight reached host Release compilation and found two missing
LocalProxy branches in feature-gated packet evidence code. Local/System modes
are now explicitly ineligible for pure-TUN packet evidence. The entire workspace
then passed all-target/all-feature clippy and 801 Rust tests in
`parity-all-features-clippy-v1.log` and `parity-all-features-rust-v1.log`. This
supersedes the narrower 754-test Rust run for release-feature coverage. The
second preflight is retained as `source-attempt-2`; signing/freezing had not begun.


## Installed 40062 defects and successor 40063

40062 completed notarization, installation and unchanged-profile verification.
Installed Off-mode latency and Local Proxy startup then exposed two older
wire guards missed by DTO-only and service-core-only tests. The fixes admit
the defined optional probe URL/status fields and Local Proxy owner capability
through the complete codecs. Unknown fields, malformed policy and wrong-mode
capabilities remain rejected. A shared Rust/Swift command fixture now covers
that envelope boundary. Preparation failure retains its exact generation until
owner and independent Authority Off observations permit cleanup acknowledgement.
Stale Stop requests remain rejected; an unavailable observation remains pending.
The orphaned-service path now recognizes failed Local Proxy owners while still
rejecting active owners, live Authority, active system proxy and unobservable
network/process state. Journals are preserved and this path does not claim Off.

Red/green records: profile-probe-envelope-red-v1.log,
local-capability-wire-red-v1.log, preparation-off-recovery-red-v1.log,
local-orphan-red-v2.log, native-wire-recovery-green-v1.log and
native-installed-fixes-full-v2.log. The first orphan test attempt failed to
compile because its test used the wrong type name; v2 reproduced the actual
old implementation failure. The linked native run passes 674 tests/25 suites.

The installed dashboard also lost focus after the first search character.
Editing refresh is now a separate module that preserves focus, selection and
scroll without storing field contents, and defers replacement during IME
composition. All 130 UI tests pass; browser checks cover sequential typing,
mid-string edits and Unicode. Real macOS IME and successor-native acceptance
remain pending. Main UI, runtime, automation, provider, proxy, rule, connection,
DNS and import modules were split by responsibility in the client-parity change;
unrelated recovery/evidence files were retained to avoid unneeded state changes.

40063 is allocated for these changed product bytes. Frozen 40062 receipts remain
immutable. Installed CFM was independently proven Off after the failed start;
CFW continues to own TUN and System Proxy. No delayed network action is pending.

Successor source checks also pass: 802 Rust tests across all workspace targets
and features, clippy with warnings denied, 130 UI tests and UI bundle build,
390 release identity/input/graph/freeze tests in the closed toolchain environment,
and all build-boundary checks. The final orphan tests cover active Local Proxy,
System Proxy and Tunnel rejection. No security guard or assertion was relaxed.
