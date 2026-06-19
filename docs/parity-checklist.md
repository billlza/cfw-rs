# Clash for Mac Parity Checklist

This checklist keeps the rebuild honest: visual parity is useful, but a page is
not complete until it is backed by the same user task flow as CFW 0.20.39.

## Current Self-Audit

- [x] Replace the first-pass dashboard-card shell with the original CFW-style
      25px status bar, 170px left menu, traffic block, runtime block and right workspace
- [x] Move General back toward the original row-based control surface instead
      of large dashboard cards
- [x] Stop blocking first paint on controller/provider HTTP requests
- [x] Remove normal-runtime fake proxy/connection/provider/rule rows when the controller is offline
- [ ] Capture screenshot-level visual parity for each route against the extracted
      renderer reference
- [ ] Prove the 3x performance target with repeatable cold-start, page-switch,
      proxy-toggle and memory benchmarks
- [ ] Remove all remaining mock-only success paths from normal runtime flows

## General

- [x] Recreate the primary CFW shell layout, status bar, runtime area and mode switcher
- [x] Expose System Proxy, TUN, Mixin, Allow LAN and startup toggles in UI
- [x] Add Rust `CoreManager` process boundary with explicit MissingBinary/MissingConfig states
- [ ] Bundle or install Apple Silicon Clash core binary into managed cores directory
- [ ] Start and supervise Clash core from Rust in production runtime
- [x] Add typed Rust controller client for `/configs`
- [x] Wire Allow LAN and IPv6 toggles to `/configs` patch
- [ ] Drive all General controls from live controller state
- [x] Create Rust `cfw-settings.yaml` store with macOS application-support paths
- [ ] Persist every original CFW setting with migration coverage
- [ ] Implement Service Mode / helper install state
- [x] Implement first-pass macOS system proxy apply and restore with network-service snapshot
- [ ] Implement TUN lifecycle and failure rollback
- [x] Remove misleading platform no-op success paths for sysproxy/helper/launchd/TUN
- [ ] Open home directory, logs directory and proxied terminal actions

## Proxies

- [x] Recreate proxy groups, selected node state and latency badges
- [x] Support UI switching for selector-like groups
- [x] Add typed Rust controller client for `/proxies`
- [x] Add `PUT /proxies/:group` command path
- [ ] Replace all Proxies mock state with live controller data in normal runtime
- [ ] Persist selected proxies across profile reloads
- [ ] Run delay tests through controller API
- [ ] Add group search, sort, filter and right-click actions
- [ ] Mirror proxy group switching in tray menu
- [ ] Apply close-connection policy after switching

## Profiles

- [x] Recreate profile list, active state and import/update surface
- [x] Define profiles/logs/cores/helpers directories under macOS app home
- [x] List profiles from the managed profiles directory and persist selected profile pointer
- [x] Import remote profile URL from Rust with YAML validation
- [ ] Import local profile files and drag/drop
- [ ] Parse subscription headers and update intervals
- [ ] Validate YAML before apply
- [ ] Support update-all, cancel update and per-profile update
- [ ] Support edit/copy/delete/open actual profile file
- [ ] Support parsers, mixin scripts and profile diff/merge
- [ ] Generate `clash://install-config` QR/import links

## Logs

- [x] Recreate log stream and level filters
- [x] Tail core log file with bounded preload
- [x] Subscribe to controller request log stream via `/logs?level=info&format=structured`
- [x] Support search, clear and pause/resume in the first-pass UI
- [ ] Support copy and open log folder
- [ ] Tail child-process logs
- [ ] Persist log preload limit and `log-level`

## Connections

- [x] Recreate live connection table and close-all affordance
- [x] Add typed Rust controller client for `/connections` REST snapshot
- [x] Subscribe to `/connections` WebSocket with REST fallback
- [x] Close one connection by ID through controller API
- [x] Add Close All command path through controller API
- [x] Add search, regex and column sorting
- [x] Add detail drawer with metadata
- [x] Add pause/resume stream and close-on-proxy-switch policy
- [ ] Add copyable metadata and per-policy disconnect rule variants

## Settings

- [x] Recreate first-pass settings groups for General, Core, macOS and Experimental
- [x] Expand visible UI taxonomy to original groups: Security, Appearance, System Proxy, Mixin,
      Proxies, Connections, Providers, Outbound, Child Processes, Profiles,
      Logs, SSID, Actions, Shortcuts, Editor, Cache and Experimental Features
- [x] Add first-pass settings read/write command for `cfw-settings.yaml`
- [ ] Persist all shell settings with schema migration
- [ ] Implement editor selection, update channels and shortcut capture
- [ ] Implement PAC/bypass list and SSID policy
- [ ] Implement fake-ip cache, DHCP server and provider controls where supported

## Tray And Protocol

- [x] Create Tauri 2 tray and focus existing window on click
- [x] Register `clash://` deep-link plumbing
- [x] Replace flat tray with checkable and nested native tray structure for
      System Proxy, TUN Mode, Mixin, Proxy Mode, Proxy Groups, Connections and More
- [x] Generate Proxy Groups submenu dynamically from live controller snapshot
- [x] Synchronize first-pass checked state for System Proxy, TUN, Mixin, Proxy Mode and proxy node selection
- [ ] Synchronize disabled state and tray delay icon with runtime state
- [x] Parse `clash://install-config`, `clash://install-profile` and `clash://quit`
- [x] Route install-config/install-profile URLs to remote profile import
- [ ] Add QR code generation/import UI

## Providers And Rules

- [x] Add visible Providers route matching original `/home/provider`
- [x] Add visible Rules route matching original `/home/router`
- [x] Add typed Rust controller client for `/providers/proxies` and `/providers/rules`
- [ ] Wire provider update and health-check commands to controller endpoints
- [ ] Replace Rules mock list with applied profile/provider rule data
