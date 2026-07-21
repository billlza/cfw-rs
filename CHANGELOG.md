# Changelog

## Unreleased

- Fix TUN/System Proxy ghost toggles: transactional `tun_mode`, writable control-session dir on Service Mode install, reap orphan managed clash-darwin by port
- General page CFW action icons: proxy export copy, bind/interfaces, core config preview, DNS query, Script note, TUN settings + restore DNS, Mixin editor, Service Mode manage trio
- Fix Service Mode / TUN under daemon ownership: hot-reload running core, auto restore DNS on TUN off (`Empty` clears), TUN row On/Off labels, bind↔Allow LAN symmetry, open Razord dashboard
- Fix glass dialog handlers nested inside GeoIP confirm (Service Mode Install / bind / Mixin / TUN settings were dead)
- Silent Start; PAC system proxy; Connections process column; tray delay title; Providers/Rules nav
- Pinned mihomo v1.19.28 + GeoIP metadb SHA-256; SMAppService TUN docs

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
