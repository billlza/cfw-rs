# Changelog

## Unreleased

- Silent Start hides the main window on launch when enabled; tray still opens the dashboard
- Profile Proxies/Rules context actions open the YAML editor focused on that section
- System Proxy: optional PAC mode (`usePacScript` + editor → macOS Auto Proxy URL / `proxy.pac`)
- Connections: Show Process column from `metadata.processPath`
- Tray delay indicator also sets the macOS menu-bar title (`Nms`)
- Primary nav includes Providers and Rules
- Pinned mihomo core **v1.19.28** (REST `/proxies` no longer merges provider nodes; use `/providers/proxies`)
- GeoIP metadb updates verify a pinned SHA-256
- Docs: TUN shipping path is SMAppService root helper (not NetworkExtension)

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
