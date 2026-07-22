# Changelog

## 0.4.0 - Unreleased

### Safety and migration

- Retire the privileged helper, external Clash-compatible cores, remote core
  installation, scripts, and PAC execution as runtime paths.
- Replace the old helper with a one-release, non-operational tombstone descriptor that can only
  stop, verify, clean, and unregister legacy state; it can never start a core.
- Remove automatic first-launch retirement. Startup leaves the existing VPN
  untouched, permits replacement profiles to be staged in a physically
  separate repository; the app performs the verified false-first retirement transaction only after explicit user
  confirmation plus a fail-closed native/profile cutover preflight.
- Block every new network mode until legacy helper/session/process state is
  gone and legacy System Proxy and DNS state has been explicitly verified.
  Ambiguous proxy or DNS ownership requires user review instead of an
  automatic overwrite.

### Network architecture

- Add typed engine API, sing-box configuration, application coordinator, and
  Apple-network adapter crates with Off-mediated Proxy/Tunnel switching.
- Add the macOS 15+, arm64 Swift protocol, ProxyAgent, Packet Tunnel System
  Extension, and bounded public `NEPacketTunnelFlow` packet-pump foundation.
- Keep the missing libbox factories and missing Rust-to-Swift production bridge
  fail-closed. Packet Tunnel also fails explicitly until authenticated
  global-context state transport replaces the invalid user App Group and Data
  Protection Keychain assumptions. The old helper, a downloaded core, and
  private packet-flow APIs are not fallbacks.

### Configuration and interface

- Replace Clash YAML/REST/WebSocket configuration with a closed app profile
  schema that projects deterministically to native sing-box JSON.
- Add closed typed profile schemas for `direct`, `block`, Shadowsocks, VMess,
  VLESS/Reality, Trojan, and Hysteria2, plus optional `route.final`. Persistent
  profiles contain canonical `credential_ref` values only; raw credentials,
  subscriptions/remote resources, scripts, executable paths, and unknown
  fields are rejected. Runtime projection produces empty secret placeholders
  and closed native injection slots. References are immutable: retries must be
  byte-identical and secret rotation requires a new UUID and profile update.
- Add missing-only credential entry backed by an atomic shared-Keychain vault.
  Renderer and bridge buffers are redacted and zeroized, present references are
  never re-prompted, and explicit two-phase garbage collection deletes only
  revision-bound orphans after repository revalidation.
- Add a private, versioned, digest-bound selected-profile record. Proxy and
  Tunnel starts require that selected profile and fail on missing or stale
  selection instead of silently using DIRECT; Off remains independently
  available.
- Separate DNS roles in both engine modes: two bounded numeric direct resolvers
  are referenced only by remote proxy endpoint `domain_resolver`
  primary/fallback fields. All ordinary DNS and route-level resolution uses one
  of two certificate-verified DoH transports explicitly detoured through the
  selected outbound; Tunnel additionally hijacks packet-flow DNS into that
  path. The pinned source patch permits one bounded retry for transport failure
  or rejected response, never on cancellation; duplicate, loopback,
  link-local, documentation, and virtual-tunnel endpoints are rejected.
- Split the Tauri composition root, UI JavaScript, CSS, platform adapters, and
  profile repository into bounded modules; remove the parallel tracked UI
  bundle.

### Supply chain and release status

- Move the workspace to GPL-3.0-or-later and pin the arm64 macOS 15 release
  toolchain and source-built libbox inputs.
- Add fail-closed release documentation for nested signing, provisioning,
  notarization, SBOM/license evidence, real packet evidence, weak-network
  recovery, resource limits, and physical-device testing.
- Replace the generic updater runtime with a project-owned, bounded metadata,
  signed-download, descriptor-relative archive admission, and atomic macOS
  swap path. Update commit now owns an exclusive engine-Off maintenance lease,
  and its cancellation boundary is linearized before any network stop.
- Release remains blocked until libbox linkage, the production Host Bridge,
  installed-identity proof for shared-Keychain provisioning and authenticated
  in-memory Tunnel injection, the pinned resolver-failover patch is present in
  the source-built libbox and verified by physical packet capture, exact
  Developer ID/provisioning, signed physical-device data-plane tests, and the
  complete publication evidence set have passed.

## 0.3.5 — 2026-07-21

Updater download progress UI (fixes “stuck on Checking…” after Download & Install).

### Updater
- Separate phases: checking / downloading / installing (no longer misuse Checking for downloads)
- Live percent + progress bar via `cfw://update-progress`
- Ignore `update-available` events while a download is in flight
- Handle “no update available” install result instead of leaving the dialog busy forever


## 0.3.4 — 2026-07-21

Quieter live streams + connections/log Diagnostics fixes (so Check for Update from 0.3.3 can pick this up).

### Diagnostics
- clash-rs `/connections` ports accept **int or string** (stops `invalid type: integer` spam)
- Logs level filter: event delegation + stream-only patch so ALL/INFO/WARNING clicks are not eaten by full re-renders
- Proxy delay **Pending** styled on `cfw-node-card`; in-flight tests keep Pending across snapshot refreshes

### Live streams (WARNING noise)
- Transient controller disconnects (`Connection reset`, `error sending request`, WS protocol reset) reconnect **quietly** — no Diagnostics WARNING spam when TUN flaps `en0`
- Clean WS close / log-level restart no longer logged as errors
- Core `[TUN] default interface changed …` remapped to **INFO** (expected mihomo monitor noise)

### Updater
- Pack `app.tar.gz` with `COPYFILE_DISABLE=1` and reject AppleDouble `._*` entries (fixes `failed to unpack ._Clash for Mac.app`)

## 0.3.3 — 2026-07-21

TUN truthfulness + product About / update feedback + Proxies/profile recovery.

### TUN (fixed)
- Switch reflects **live handoff** (`tun.enable` + managed root core), not a stale disk flag
- Fresh launch defaults to **Off** unless Service Mode actually owns a TUN-capable core
- Service Mode always spawns **mihomo** for TUN (clash-rs controller-ready ≠ working utun)
- Handoff readiness uses **controller API + netstat** — unprivileged `lsof` cannot see root listeners
- Failed handoff scrub `cache.db` (root-owned) and wait for ports before restarting in-process core
- Helper `serve` processes an existing control session **immediately** (no 5s first-wait race)
- After TUN up: sync persisted **Rule/Global** mode; auto-escape **Global+DIRECT** blackhole (looked like “TUN broken”)
- Heartbeat 10s / stale 90s to reduce helper tearing down a live TUN session
- System Proxy toggles **never** mutate `tun_mode`; UI re-syncs TUN after proxy changes

### Proxies / Profiles
- Entering Proxies, TUN toggle, settings-changed, and profile switch all **re-fetch controller snapshot**
- Empty mode chrome hidden when controller has no groups; clearer empty copy
- Removed meaningless Profiles hover 4-icon bar (use card click + right-click menu)
- Profile switch rollback re-applies previous profile; `controller_snapshot` no longer fails wholly when connections lag
- `set_proxy_mode` persists `runtime_mode`; hot-reload failures are no longer silent success

### About / Check for Update
- App menu **About Clash for Mac** and **Check for Update…** open the native product card

## 0.3.2 — 2026-07-21

Update UX + measured clash-rs vs mihomo answers on Apple Silicon.

### Updates
- macOS app menu: **Check for Update…** under About Clash for Mac
- Startup silent check; General header shows **→ vX.Y.Z** when a newer release exists
- Confirm → download/install via `tauri-plugin-updater` (GitHub `latest.json`)

### Measured kernel compare (not docs-only)
- `scripts/kernel_compare.py` runs clash-rs and mihomo on high localhost ports
- Ships `resources/benchmarks/kernel-compare-latest.json` with cold-start, controller API, delay, and weak-timeout burst metrics
- General **Core Bench** row + Feedback panel show the measured speedup / reliability deltas
- This host’s run: **~1.27×** faster cold start & controller API vs mihomo; weak-net / delay success tied at 100% — **not** a CFW 「3×」 claim

## 0.3.1 — 2026-07-21

Apple Silicon–only hardening with a Rust core default. Version stays **0.3.1**.

### What is stronger than CFW / prior builds (verifiable)
- **Default core: clash-rs (Rust)** on arm64; mihomo kept only as automatic fallback
- **Tauri 2 native shell** (not Electron) — smaller process model than CFW’s Electron
- **Apple Silicon only** — no Intel / Universal Binary tax
- Typed sysproxy / DNS / Login Item / helper paths from earlier 0.2–0.3 work remain

### Explicit product decisions (not unfinished “todos”)
- **UI:** Tauri + WebKit (`ui/`) is the product UI. React is **not** stronger than Tauri and is **not** a migration target.
- **TUN:** SMAppService privileged helper is the **production** path. Network Extension is research-only, not shipped.
- **App Sandbox:** **Rejected** for the main app while root helper TUN is required (Sandbox and root helper conflict).
- **「3× CFW」:** Not advertised. Perf CI records metrics only (`claim_3x_cfw: false`) until a same-machine CFW baseline exists.

### Platform
- Docs/CI refuse `x86_64` / lipo (`scripts/assert_apple_silicon.sh`)
- Sparkle remains cancelled (`tauri-plugin-updater` since 0.2.0)

### Core
- `CoreKind` default = `clash_rs`
- Pinned clash-rs **v0.10.7** aarch64 (checksum-verified)
- `--compatibility` is opt-in via `CFW_CLASH_RS_COMPAT` (avoids first-boot GeoIP stall)
- Mihomo fallback on missing binary / start / controller readiness failure

## 0.3.0 — 2026-07-21

Delay-test correctness + TUN stability for Apple Silicon.

### Proxies / delay test
- Failed and timed-out probes show **Timeout** (no more **N/A**)
- After one full round, every tested node has a final state (no leftover **Pending**)
- Adaptive concurrency (`hardwareConcurrency`, clamped 4–16; drops to 2 when backgrounded)
- Visible nodes probed first; incremental delay label patching (no full-page flash per chunk)
- Cancel on group switch / leave Proxies / second click
- Network default-route changes mark delay badges stale

### TUN
- Launch reconcile: if `tun_mode` + Service Mode Enabled → full root handoff (not a half start)
- TUN owns core → config changes force helper respawn (hot reload skipped for utun/routes)
- Safer defaults: `stack: mixed`, `strict-route: true`, DNS hijack `any:53` + `[::]:53`
- TUN settings Save always re-applies runtime config when TUN is on

### Stack
- Continues 0.2.0 platform path (SCPreferences proxy/DNS, Login Item, updater)

### Not included in 0.3.0 (do not treat as shipped)
- Network Extension / App Sandbox / React UI migration
- mihomo rewrite or clash-rs default cutover *(cutover landed in 0.3.1)*
- Proven 「3× CFW」 CI gates
- Universal Binary (permanently rejected; Apple Silicon only)
- Sparkle (superseded by tauri-plugin-updater)

## 0.2.0 — 2026-07-21

Apple Silicon performance and platform hardening release (P0–P2).

### P0
- ControllerClient process-wide singleton / reqwest connection pool reuse
- cfw-helper control-session supervision is FSEvents/`notify` event-driven (5s heartbeat fallback; no fixed 500ms poll)

### P1
- Connections page incremental DOM patching (no full-page `innerHTML` on every WS tick)
- Silent Start uses `ActivationPolicy::Accessory` + Dock hide; tray Show restores Regular + Dock
- Start at Login uses `SMAppService::mainAppService` Login Item (migrates off user LaunchAgent)

### P2
- DNS set/restore via SCPreferences with `networksetup` fallback
- `tauri-plugin-updater` + GitHub Releases `latest.json` (arm64)

### Stack (carried from Unreleased)
- Rust **1.97.1**; YAML via noyalib `compat-serde-yaml`; reqwest **0.13**; Tauri **2.11.5**
- System Proxy SCPreferences path; UI `ui/src/` + esbuild

## 0.1.0 — 2026-07-20

### Beta release candidate

- Apple Silicon–only Clash for Mac (Tauri 2) rebuild of CFW 0.20.39 core daily path
- Bundled mihomo core provisioning + CoreManager start/stop
- Profiles: remote URL import, local/text import, drag-drop, update scheduler, apply, edit, QR
- Proxies / Providers / Rules / Connections / Logs wired to live controller (no offline fake rows)
- System Proxy with network-service snapshot restore + editable bypass list
- Service Mode via SMAppService + privileged helper for TUN (requires Developer ID + Login Items approval)
- Tray menu + `clash://` deep links; optional tray latency tooltip
- Default `profile.store-selected`; Logs Copy + Open Folder
- Developer ID signed, notarized, and stapled (DMG + app)
- Release gate documented in `RELEASE.md`
