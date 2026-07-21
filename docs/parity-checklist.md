# Clash for Mac Parity Checklist

Honest status vs CFW 0.20.39 for the **0.1.0 beta** gate in [`RELEASE.md`](../RELEASE.md).
Items marked beta-out-of-scope do not block distribution.

## Current Self-Audit

- [x] CFW-style shell: status bar, left nav, traffic/runtime, workspace
- [x] Non-blocking first paint (controller offline shows empty, not fake rows)
- [x] No silent platform no-op success for sysproxy / helper / TUN
- [ ] Screenshot-level visual parity per route *(beta out of scope)*
- [ ] Proven 3× performance CI gates *(beta out of scope)*

## General

- [x] Layout, System Proxy / TUN / Mixin / Allow LAN / startup toggles
- [x] General row action icons (Port terminal/sync, Allow LAN info/interfaces, Core preview/DNS/script, TUN settings/DNS restore, Mixin edit, Service Mode manage)
- [x] Editable bind-address + network interfaces dialog
- [x] Runtime config preview + controller version/dashboard URL copy
- [x] `CoreManager` + MissingBinary / MissingConfig
- [x] Bundle / provision Apple Silicon mihomo (`clash-darwin`) into managed cores dir
- [x] Start / stop / supervise core from Rust (in-process; root daemon when TUN)
- [x] Typed `/configs` client; Allow LAN + IPv6 + bind-address patches
- [x] `cfw-settings.yaml` + Application Support paths + schema_version
- [x] System proxy apply + network-service snapshot restore
- [x] Service Mode via SMAppService + privileged helper (Install / Uninstall / Login Items)
- [x] TUN lifecycle handoff to root daemon (fails loudly if unsigned / unapproved)
- [x] Reveal home directory action
- [x] GeoIP database status + click-to-update (`geoip.metadb` / `Country.mmdb`)
- [x] Honest product version badge (`0.1.0`; CFW 0.20.39 is parity target only)
- [x] Random mixed-port toggle wired to core start
- [ ] Mode switcher on General page *(lives on Proxies; CFW also keeps modes there)*
- [ ] Every original CFW setting with full migration *(partial — extra flattened)*
- [ ] Full proxied Terminal spawn *(beta out of scope — Port copies export commands)*

## Proxies

- [x] Groups, selection, latency badges from live controller
- [x] `PUT /proxies/:group`; tray proxy-group submenu
- [x] Delay tests via controller API
- [x] Search / filter in UI
- [x] Close-connection policy after switch (setting + command path)
- [x] Persist selected proxies across profile reloads *(default `profile.store-selected: true`)*
- [ ] Full right-click action parity *(partial)*

## Profiles

- [x] List / active pointer / remote URL import with YAML validation
- [x] Local / text import + drag-drop
- [x] Subscription headers + update interval metadata + scheduler
- [x] Per-profile update; apply active; edit / save / delete / reveal
- [x] Safe parser script + mixin YAML merge
- [x] QR (`profile_qrcode_svg`) + `clash://` install-config routing
- [ ] Update-all cancel mid-flight UI polish
- [ ] Monaco-style diff editor *(beta out of scope)*

## Logs

- [x] Core log tail + controller `/logs` WebSocket
- [x] Search / clear / pause; level filter
- [x] Copy + open log folder
- [ ] Child-process log tail *(beta out of scope)*

## Connections

- [x] Live table, WebSocket + REST fallback, close one / close all
- [x] Search / regex / sort / detail drawer / pause
- [ ] Richer per-policy disconnect variants *(beta out of scope)*

## Settings

- [x] Full taxonomy visible; read/write `cfw-settings.yaml`
- [x] Fake-IP cache flush via controller
- [x] Editable system-proxy bypass list (Settings)
- [x] Editable PAC script UI *(Use PAC Script + editor → Auto Proxy URL)*
- [ ] SSID policy *(not implemented — must not claim configured)*
- [ ] DHCP server experimental *(not implemented)*
- [ ] Shortcut capture UI *(keyboard shortcuts exist; no recorder)*
- [x] Connection process column *(Show Process toggle + processPath)*

## Tray And Protocol

- [x] Tray + nested System Proxy / TUN / Mixin / Mode / Groups / Connections
- [x] `clash://install-config|install-profile|quit`
- [x] QR generation UI for profiles
- [x] Tray delay tooltip when `show_tray_proxy_delay_indicator`
- [x] Tray delay menu-bar title (`set_title`) when indicator on

## Providers And Rules

- [x] Providers + Rules routes
- [x] Providers / Rules in primary navigation
- [x] Live `/providers/*` + `/rules` snapshots
- [x] Provider update + health-check commands (single + batch)
