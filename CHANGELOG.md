# Changelog

## 0.3.3 — 2026-07-21

TUN truthfulness + product About / update feedback.

### TUN (fixed)
- Switch reflects **live handoff** (`tun.enable` + managed root core), not a stale disk flag
- Fresh launch defaults to **Off** unless Service Mode actually owns a TUN-capable core
- Service Mode always spawns **mihomo** for TUN (clash-rs controller-ready ≠ working utun)
- Handoff readiness uses **controller API + netstat** — unprivileged `lsof` cannot see root listeners and previously false-failed while utun was already up
- Failed handoff scrub `cache.db` (root-owned) and wait for ports before restarting in-process core
- Helper `serve` processes an existing control session **immediately** (no 5s first-wait race)
- System Proxy toggles **never** mutate `tun_mode`; UI re-syncs TUN after proxy changes
- `write_settings_snapshot` cannot ghost-flip TUN; reconcile emits `cfw://settings-changed`

### About / Check for Update
- App menu **About Clash for Mac** and **Check for Update…** open a ChatGPT-style product card (version, release date, status)
- Checking / up-to-date / update-available / install all show in that dialog (no silent no-op)

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
