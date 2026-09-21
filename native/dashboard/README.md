# Native overview integration

This is the first implemented 0.5.0 presentation slice. It is a real SwiftUI
library and AppKit window hosted by the existing application process. The
`native-dashboard` Cargo feature adds **Window → Native Overview** (⇧⌘O).
The old dashboard and every existing network command remain the control surface.
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

`include/cfm_native_dashboard.h` describes the main-thread presentation ABI.
Frames are copied synchronously, versioned, bounded to 32 KiB and decoded into
closed Swift enums. Each observer has an increasing session ID; frame ordering
is enforced within that session. A superseded observer cannot update or invalidate
its replacement. Only one open may await admission at a time. Each observer has
at most one outstanding main-thread delivery; the watch channel coalesces newer
state. There are no idle polling timers.

An accepted present transfers one Rust-owned close-notification reference to
Swift. Closing/replacing the window consumes its callback exactly once and cancels
only that observer. Failed presents retain nothing. A locale event listener is
removed when observation ends. Delivery failures remain visible as stale state.

The UI uses native navigation, typography, symbols, semantic styles,
scrolling and keyboard affordances. macOS 26+ uses a native glass toolbar button
inside `GlassEffectContainer`; macOS 15 and reduced transparency/increased contrast
use a standard bordered control. There are no decorative animation timers.

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
linked library's localized resources, checks replay/session isolation and closes
the windows. Its input is explicitly a presentation fixture, not live VPN proof.
It never loads a native networking framework or installs a service.

Swift tests cover wire validation, four languages, window callbacks, and rendering
at 850 × 603 in both appearances. With an existing `CFM_NATIVE_RENDER_DIR`, they
write PNG render fixtures and 10,000 raw decode/model timings. These debug component
timings exclude rendering, app launch, RSS, energy and network traffic. They do
not establish any performance improvement over the full 40073 application.

Remaining: extract and bind mutation use cases without Tauri coupling; migrate
profiles, nodes, settings, connections, rules and diagnostics; native app lifecycle,
menu bar and update/migration composition; screen-reader and oldest-OS tests;
installed real-state validation and full comparative performance/network evidence.
