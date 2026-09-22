# Native overview integration

**Status — user rejected this visual direction on 2026-09-22.** The one-page
Overview and sample-data preview are retained only as integration experiments.
They are not the requested 0.5 UI. Preserve the complete 0.4 layout, details and
interaction paths while adopting native component materials; the binding contract
is `docs/planning/0.5.0-ui-fidelity-contract.md`. Do not present this experiment as
the corrected design or expand it into a replacement workflow.

This directory retains the rejected overview layout and reusable network-control integration. It is a real SwiftUI
library and AppKit window hosted by the existing application process. The
`native-dashboard` Cargo feature adds **Window → Native Overview** (⇧⌘O).
The native view controls core, System Proxy and TUN through the same Rust use cases
as the existing dashboard. Other functions still use the existing dashboard.
There is no second Rust coordinator, Swift network state machine or new daemon.

The feature is opt-in and development-only. `build.rs` rejects release-profile
builds with this feature until signed bundle composition and functional parity
have been implemented. Do not enable it for a 40073 candidate or copy development
products over the installed application. Building and testing the integration
does not allocate a new signed candidate, change the package version, or publish.

## Data and ownership

The adapter subscribes to the existing `EngineModeCoordinator` watch channel.
It waits for startup reconciliation so the initial default cannot be mistaken
for an independently observed Off. Failed observations display Unknown and the
retained failure, not an inactive or connected state. Viewing, reloading, changing
language and closing this window do not send network commands.

`include/cfm_native_dashboard.h` describes the main-thread version 2 presentation
and intent ABI.
Frames are copied synchronously, versioned, bounded to 32 KiB and decoded into
closed Swift enums. Each observer has an increasing session ID; frame ordering
is enforced within that session. A superseded observer cannot update or invalidate
its replacement. Only one open may await admission at a time. Each observer has
at most one outstanding main-thread delivery; the watch channel coalesces newer
state. There are no idle polling timers.

An accepted present transfers one Rust-owned close-notification reference to
Swift. Closing/replacing the window consumes its callback exactly once and cancels
only that observer. An accepted command retains a separate Rust owner until the
existing serialized operation completes. A close cannot release its mutation
lease or terminate networking work. Failures reach the existing application log
even when their window has closed. Failed presents retain nothing. A locale event listener is
removed when observation ends. Delivery failures remain visible as stale state.

The UI uses native navigation, typography, symbols, semantic styles,
scrolling and keyboard affordances. macOS 26+ uses a native glass toolbar button
inside `GlassEffectContainer`; macOS 15 and reduced transparency/increased contrast
use a standard bordered control. There are no decorative animation timers.

## Commands and recovery

The three Tauri commands and the native adapter call `engine_controls.rs`.
It retains the existing mode queue, capability/retirement checks, selected profile,
authorization and coordinator transitions. No command drives a native service
directly. The native adapter passes its exact last-displayed snapshot into that
queue; a newer engine generation cannot silently substitute for the user's view.

Rust projects desired switch values separately from observed connection status.
Swift displays pending work without optimistic connection changes. Replayed,
stale, unavailable and overlapping requests are refused; only a completion with
the current request ID clears the pending action. Stop remains available when
start admission is denied, once the current request completes, matching the
existing dashboard's one-request-at-a-time interaction.

A matching failed, approval-pending or non-ready mode exposes an explicit Retry
or Continue Approval action. Ready/in-flight modes cannot restart through a
same-value toggle. If an explicit retry still needs tunnel approval, the adapter
reuses the existing `SMAppService` system-settings navigation on the main thread.
That API requests navigation; it is not proof of approval or of a visible settings
pane. Navigation is never triggered by simply observing or closing the window.

Journal/process start-admission observation is sampled once per projected frame,
off the UI thread. The command revalidates admission under the existing mutation
lease; the projection is not an authorization credential or a cached permission.

## Verification

Use the repository's pinned/private Rust environment and verified Cargo wrapper:

```sh
cargo test --locked --offline -p cfw-application
cargo test --locked --offline -p cfw-tauri-shell --features native-dashboard \
  --bin clash-for-mac --test native_dashboard_ffi
cargo clippy --locked --offline -p cfw-application -p cfw-tauri-shell \
  --features native-dashboard --all-targets -- -D warnings
xcrun swift test --package-path native/dashboard -Xswiftc -warnings-as-errors
```

The shell still requires its real UI build, produced with pinned Node/npm and
`npm ci --ignore-scripts && npm run build` in `apps/cfw-tauri-shell`. Do not create
an empty `ui/dist` to bypass that dependency.

The standalone Rust FFI test creates actual SwiftUI/AppKit windows, loads the
linked library's localized resources, checks replay/session isolation, Rust–Swift–Rust control callbacks, pending/failed
completion, explicit approval retry and exactly-once close ownership. Its input is explicitly a presentation fixture, not live VPN proof.
It never loads a native networking framework or installs a service.

Swift tests cover wire/command validation, four languages, window callbacks, and failed/approval
rendering at 850 × 603 in both appearances. With an existing `CFM_NATIVE_RENDER_DIR`, they
write PNG render fixtures and 10,000 raw decode/model timings. These debug component
timings exclude rendering, app launch, RSS, energy and network traffic. They do
not establish any performance improvement over the full 40073 application.

Remaining: migrate profiles, nodes, settings, connections, rules and diagnostics; native app lifecycle,
menu bar and update/migration composition; screen-reader and oldest-OS tests;
installed real-state validation and full comparative performance/network evidence.

## Inspecting the UI locally

`Preview/build-preview.sh` produces an independently named, locally signed UI
preview for side-by-side inspection. It uses this exact presentation library,
shows a persistent sample-data notice and disables every network control. It
never starts the production Rust host or its native networking services. See
`Preview/README.md` for scope, packaging and the actual AppKit self-check.
