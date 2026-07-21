# Architecture Baseline

## Goal

Rebuild the final Apple Silicon macOS flavor of Clash for Windows with:

- equivalent UI structure
- equivalent feature surface
- better internal boundaries
- no Intel macOS support

## Reverse-Engineered Baseline

The `0.20.39` macOS ARM64 app package establishes the product shape:

- Electron shell with tray and frameless dashboard window
- renderer-driven configuration UI
- local Clash core controlled over `127.0.0.1`
- auth via controller `secret`
- bundled macOS binaries:
  - `clash-rs` (Watfaq; **default** Rust core)
  - `clash-darwin` (pinned mihomo; automatic fallback)
  - `sysproxy` (historical CFW; our path uses SCPreferences)
  - `clash-core-service` (historical CFW; our path uses SMAppService `cfw-helper`)
- settings persisted to `cfw-settings.yaml`
- privileged operations delegated to helper/service logic
- **platform lock:** `aarch64-apple-darwin` only — never Intel / Universal Binary
- **UI:** Tauri 2 + WebKit — React is not a product migration target
- **TUN:** SMAppService helper is production; Network Extension / App Sandbox are not

## Required 1:1 Feature Buckets

These should be treated as compatibility scope, not optional polish:

1. Dashboard navigation structure
2. Tray menu structure and mode toggles
3. Profile import/update lifecycle
4. Proxy group selection and persistence
5. Mixed port / external controller / secret flow
6. System proxy enable/disable
7. TUN mode lifecycle
8. Connections and logs views
9. `clash://` protocol handling
10. Auto-launch and window restore behavior

## Deliberate Departures

These are intentional improvements, not regressions:

1. Apple Silicon only
   - target `aarch64-apple-darwin`
   - do not carry Intel code paths, Rosetta assumptions, or dual-arch packaging
2. Stronger process boundaries
   - UI shell must not directly own privileged behavior
   - helper operations should be expressed as explicit commands/contracts
3. Cleaner platform abstraction
   - macOS-specific service and proxy code should not leak across the domain
4. Safer configuration and state model
   - typed settings/state instead of renderer-spread implicit behavior

## Recommended Technical Direction

### Shell

Use a Rust-first desktop shell, with Tauri 2 as the most practical path to
pixel-accurate reconstruction of the existing information architecture on macOS.

Reason:

- The original product is visually web-shaped
- Recreating the same layout and interaction model is lower risk in a WebKit
  shell than in a pure native widget tree
- Tauri on macOS uses the system `WKWebView`, which aligns well with an
  Apple-Silicon-only strategy

### Core

Model the application around explicit services:

- `CoreManager`
- `ProfileManager`
- `ProxyStateStore`
- `SettingsStore`
- `ControllerClient`
- `PlatformService`

### Privileged Operations

Treat helper install and TUN/proxy mutations as a separate subsystem:

- UI requests action
- shell validates state and emits a typed command
- platform layer executes via helper boundary
- helper returns typed result/error

Do not hide privilege boundaries inside ad-hoc shell commands.

## First Delivery Slices

1. Read/write settings and restore dashboard state
2. Launch bundled Clash core and speak controller API
3. Rebuild tray/menu and mode switching
4. Rebuild profiles and proxies screens
5. Rebuild system proxy flow
6. Rebuild helper + launchd flow
7. Rebuild TUN mode flow

