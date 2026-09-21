# Clash for Mac 0.5.0

Prepared 2026-09-20; implementation started 2026-09-22. The development-only
SwiftUI observation window now uses the existing Rust coordinator. Full UI parity,
standalone native hosting, installed acceptance and product performance gains
remain open; see [implementation status](planning/0.5.0-implementation-status.md). The functional comparison baseline is the frozen
0.4.0 build 40073, source `9e2f76cdd7ffb286614a7bc6fe55e75d3fc7a5b2`.
Its GA publication has its own evidence requirements and remains separate work.

## Product contract

Make the application attractive, quick and practical with a native SwiftUI
interface and Apple's Liquid Glass controls. Preserve every supported 0.4.0
operation, persisted user choice and network/security contract. UI work must not
change routing, silently choose a node, restart the engine, weaken authentication,
or reinterpret imported profiles. Dependency and network improvements have
separate changes and acceptance evidence so regressions can be attributed.

Keep Apple Silicon and macOS 15+ support. Use native Liquid Glass where the
system supports it (macOS 26+); earlier supported systems use standard SwiftUI
materials with the same functions. A visual improvement must not require users
to give up an otherwise supported OS or accessibility setting.

## Interface direction

Use a native sidebar, toolbar, content area and optional inspector. Lead with
connection state, selected profile/node and useful traffic information. Make
routine actions easy to find and keep advanced controls available in context.

| Area | Intended experience |
| --- | --- |
| Overview | Clear connection state and separate core, System Proxy and TUN controls; useful upload/download history; actionable errors |
| Proxies | Searchable groups and nodes; current selection; cancellable latency tests; favorites only if they preserve selection semantics |
| Profiles | File, URL, text and supported legacy imports; editable profiles, QR sharing, refresh status and credential prompts |
| Connections | Native table, search, sorting, inspect/close actions and bounded live updates |
| Rules and providers | Explain rule order and provider state; refresh and health checks without changing fallback/group semantics |
| Logs and diagnostics | Level filtering, pause/resume, retained errors, copy/export with the existing secret-redaction boundary |
| Settings | Native forms for runtime, DNS/IPv6, ports/LAN, startup, language, appearance, shortcuts and Wi-Fi automation |
| Menu bar | Fast status, profile/node selection and existing network actions; keyboard access and localized labels |

Use system typography, SF Symbols, semantic colors and standard focus, selection,
menus, sheets and alerts. Apply Liquid Glass to navigation and important controls;
use solid or standard-material surfaces for dense tables, logs and settings.
Group nearby custom glass controls in `GlassEffectContainer`. Do not stack blur
layers or run decorative animations while the window is hidden. Respect Reduce
Motion, Reduce Transparency, increased contrast, VoiceOver and keyboard-only use.
Verify light/dark appearance and all four languages at the existing minimum
850 × 603 window size, large windows and multiple display scales.

These choices follow Apple's [materials guidance](https://developer.apple.com/design/human-interface-guidelines/materials),
[Liquid Glass adoption guidance](https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass),
and [GlassEffectContainer contract](https://developer.apple.com/documentation/swiftui/glasseffectcontainer).

## Architecture and migration boundary

The current presentation is a Tauri/WKWebView host, not a SwiftUI application.
The existing command surface in `apps/cfw-tauri-shell/src/main.rs` and
`apps/cfw-tauri-shell/src/commands/` includes application orchestration. Replacing
HTML/CSS therefore requires an explicit host-adapter migration, even though the
intended user-facing change is the UI.

Target composition:

```text
SwiftUI scenes, settings and menu bar
        ↓ typed asynchronous application facade
Rust application use cases and serialized coordinator
        ↓ existing engine/platform/native bridge contracts
Global Authority / ProxyAgent / Packet Tunnel / pinned libbox
```

`cfw-application` already owns state transitions without depending on Tauri or
Swift. Keep that authority. Extract only the orchestration currently coupled to
Tauri into a reusable Rust application service; the current command handlers
become adapters during migration. Do not implement a second coordinator in Swift
or let views invoke libbox or privileged network APIs directly.

Use a small versioned, in-process C ABI between the native host and Rust service,
with explicit buffer ownership, opaque session handles, typed results, cancellation,
bounded event delivery and shutdown. Existing `CFWNativeBridge` is the Rust-to-Apple
network boundary; do not mistake it for an already implemented Swift-to-Rust UI
facade. Validate the new direction before committing the full screen migration.
Keep Swift rendering state on `MainActor`; perform filesystem, Keychain, parsing,
network calls and substantial event processing away from it. Map errors and
pending/unknown states faithfully. A dropped UI subscription must not stop the VPN.

The final SwiftUI host must preserve bundle IDs, Team identity, entitlement and
Keychain access-group contracts, service registration, extension activation,
deep links and installation transactions. Any necessary host/signing composition
change needs installed validation. Development may compare two frontends, but
only one authority owns networking; do not ship two competing state machines.

## Functional parity

The machine-readable [command inventory](planning/0.5.0-command-baseline.json)
is extracted from the frozen source. It includes internal host commands; each
needs a mapped implementation or a documented equivalent host lifecycle, not
necessarily a new visible button. It does not replace tests of command results,
events, storage and side effects.

| Contract | Required evidence before switching the default UI |
| --- | --- |
| Core/System Proxy/TUN/combined modes | Same state transitions, actual OS readback, traffic and exact restoration |
| Profile/node selection and online changes | Same validated configuration/credential binding and persistent choices; no extra engine restart |
| Imports, editing and subscriptions | Accepted fixtures produce equivalent profiles; invalid/unsupported inputs remain explicit failures |
| Provider groups and ordered rules | Preserve URL-test, fallback, load-balancing, detour and routing semantics |
| Credentials and garbage collection | Existing Keychain ownership, revision checks, missing-only provisioning and redaction |
| Runtime and DNS preferences | Existing precedence, IPv6 behavior, LAN exposure checks, port/MTU settings and persistence |
| Connections, logs and latency probes | Accurate data, bounded memory, explicit cancellation and subscription cleanup |
| Automation, login items and shortcuts | Existing permission prompts, saved choices, run-loop responsiveness and error behavior |
| Four languages and accessibility | Simplified/Traditional Chinese, English and Japanese; native menus and saved language survive relaunch |
| Startup/quit/reload/update/migration | No main-thread I/O stalls, no late engine installation after quit, no unintended disconnect on UI changes |

For each family, run existing Rust/Swift tests plus real adapter integration tests
and installed UI scenarios. Compare old and new commands, emitted events and
network effects on the same inputs. Keep failure samples. A screen that renders
or a compile-only bridge does not close functional parity.

## Performance acceptance

The following are engineering targets, not measured results. Record a 40073
baseline before optimization. Use the same hardware, OS/build, power mode,
profiles, node/server and workload; include an M5 MacBook Air and the lowest
supported macOS environment when available. Record raw measurements and process
identities for the host, Authority, ProxyAgent, Provider and any web-content
processes. Report cold/warm launch separately and distribution tails, not only
the best sample.

| Metric | 0.5.0 target |
| --- | --- |
| Cold launch to usable controls | p95 at least 20% lower than 40073 over 30 launches; core startup measured separately |
| Idle total resident memory | At least 20% lower after stabilization, including all product processes |
| Idle CPU and energy | No regression across repeated 10-minute samples; minimize timers and wakeups |
| Common interaction feedback | p95 under 100 ms with no synchronous network/disk work on the main actor |
| Lists and live data | Smooth 60 Hz scrolling for 10,000 nodes/connections; bounded logs and event queues; measure hitch rate |
| Network throughput/latency | No material regression in repeated TCP/UDP/QUIC runs; target at least 10% improvement only where profiling identifies a product bottleneck |
| Long-running resources | No continuing memory/queue growth during a 3-hour bounded soak and repeated connect/disconnect cycles |

Use Release builds and Instruments (SwiftUI, Time Profiler, Hangs/Hitches,
Allocations and energy/wakeups). If variation hides an improvement, report it as
unproven. Establish the no-regression threshold before comparative runs and retain
both distributions. Follow Apple's [SwiftUI profiling guidance](https://developer.apple.com/videos/play/wwdc2025/306/).

## Dependencies and network support

Recheck official stable releases at implementation start and before the 0.5.0
freeze. Pin compiler, direct/transitive dependencies, upstream commits, build tags
and patches; record compatibility exceptions. Do not move 0.4.0's frozen inputs.

The 2026-09-20 check found [Rust 1.98.1](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/)
and [sing-box 1.14.1](https://github.com/SagerNet/sing-box/releases/tag/v1.14.1)
as current stable releases, already used by 40073. The crates.io review of 22
direct workspace dependencies found one newer stable line:
[`saphyr-parser` 0.1.0](https://crates.io/crates/saphyr-parser), versus 0.0.12.
Evaluate its event API, alias/depth/event limits and invalid-input behavior before
upgrading. This direct-dependency check is not a claim that every transitive crate
or application-local dependency is current. See the
[dated dependency snapshot](planning/0.5.0-dependency-snapshot.json).

Keep the six existing engine patches until their exact behavior is covered by
upstream code and regressions. Re-run both original and patched Go dependency
scans; retain the offline source/build correspondence. Compiler or engine version
increases alone do not prove better throughput or reliability.

Translate “strongest VPN support” into tested capabilities:

1. Preserve current supported proxy transports, WireGuard, encrypted DNS,
   IPv4/IPv6, rule routing and System Proxy/TUN combinations through the UI migration.
2. Test UDP/QUIC, MTU/fragmentation, IPv6-only/NAT64, DNS failures, captive portals,
   sleep/wake, same-interface lease changes and Wi-Fi/hotspot handovers with real
   packet-flow evidence. Retain credential/identity rejection and cleanup checks.
3. Evaluate upstream [OpenVPN](https://sing-box.sagernet.org/configuration/endpoint/openvpn-client/)
   and [OpenConnect](https://sing-box.sagernet.org/configuration/endpoint/openconnect/)
   client support as explicit additive
   work: profile schema/import, vault handling, compiled Apple backend, DNS/routes,
   authentication and real-server interoperability must all be supported. Upstream
   availability is not evidence of CFM support.
4. Evaluate kill-switch/leak prevention as a separate OS/network policy feature.
   Specify failure states and prove no unintended direct traffic before advertising
   it. UI errors, automatic reconnect or an Off indicator are insufficient.
5. Show a capability's actual support and failure reason. Do not imply access to
   commercial VPN accounts/servers, provider-specific obfuscation, traffic-analysis
   defenses or post-quantum services from a local switch.

Use the versioned sing-box source and official
[WireGuard endpoint documentation](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)
for protocol contracts. Living documentation may include 1.15-only fields; do not
project those into the stable 1.14.1 build.

## Implementation sequence and exits

1. **Baseline:** freeze the functional command/storage/event inventory; record
   installed screenshots and performance traces without altering active networking.
2. **Application facade:** extract the necessary Tauri orchestration, build the
   Swift/Rust boundary and prove real read-only snapshots, cancellation and shutdown.
3. **Native interface:** implement design tokens and all screen families with real
   state; complete language, accessibility and action parity before changing default UI.
4. **Performance and stable dependencies:** optimize observed bottlenecks, update
   compatible inputs in separately reviewable changes, and repeat parity/network tests.
5. **Additive VPN work:** implement only capabilities that pass complete config-to-
   packet-flow tests. Track unsupported cases explicitly rather than broadening claims.
6. **Release:** signed/notarized 0.5.0, safe 0.4.0 upgrade, real installed acceptance,
   GPL/source/SBOM closure and verified public bytes. Rollback compatibility must be
   documented before any persistent format change.

0.5.0 is ready only when functional parity, visual/accessibility review and measured
performance improvements all have evidence. The first development integration does not change the current application version,
dependency locks, network settings or installed application. On 2026-09-22 the user
authorized 0.4.0 remediation and 0.5.0 implementation to proceed in parallel;
0.4.0 publication is no longer a prerequisite for development work.
