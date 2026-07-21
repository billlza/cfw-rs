# Changelog

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
