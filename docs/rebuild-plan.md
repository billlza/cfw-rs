# Rebuild Task List

This file translates the reverse-engineered CFW macOS shape into a Rust rebuild
work plan.

The detailed completion gate lives in
[`parity-checklist.md`](/Users/bill/cfw-rs/docs/parity-checklist.md). The
performance/stability gate lives in
[`performance-stability-targets.md`](/Users/bill/cfw-rs/docs/performance-stability-targets.md).

## General

- Recreate dashboard overview and runtime status: first-pass UI done
- Recreate `Global / Rule / Direct / Script` mode switching: first-pass UI done
- Recreate system proxy and TUN toggles: first-pass UI done
- Recreate startup, restore and single-instance behavior
- Next real vertical slice: profile import/apply and core binary provisioning
- `SettingsStore` now has a first-pass Rust implementation for
  `cfw-settings.yaml` and managed macOS paths
- `ControllerClient` now has typed `/configs`, `/proxies`, `/connections`,
  mode patch, proxy selection, close-all command paths and Clash WebSocket URLs
- `CoreManager` now has a process boundary for status/start/stop, with explicit
  missing-binary and missing-config failures
- The verified desktop target is the Tauri bundle
  `/Users/bill/cfw-rs/target/debug/bundle/macos/Clash for Mac.app`; the static
  HTTP server is only a smoke-test fallback and is not a product runtime.

## Proxies

- Rebuild selector group list from controller API
- Rebuild current selection persistence
- Rebuild tray quick switching parity
- Rebuild delay indicator and liveness rendering
- Controller-backed proxy groups and tray quick switching are now wired; delay
  testing and persistence are the next gates

## Profiles

- Rebuild import from URL/file
- Rebuild update scheduler and refresh actions
- Rebuild YAML validation and parse errors
- Rebuild selected profile persistence and migration
- First-pass list/import/update UI exists; filesystem lifecycle is the next gate

## Logs

- Rebuild core log stream
- Rebuild helper and shell diagnostic stream
- Rebuild level filters and copy/export actions
- Core log tail and request-log WebSocket are wired; child-process logs,
  copy/export and log-level persistence are next

## Connections

- Rebuild live connection table
- Rebuild close-all action
- Rebuild traffic counters and live refresh
- `/connections` WebSocket, search/sort/pause/detail and close-on-switch are
  wired; metadata copy and richer filters are next

## Settings

- Rebuild launch-at-login
- Rebuild random controller port
- Rebuild tray indicator preferences
- Rebuild deep-link registration state
- Rebuild migration/import surface from old CFW paths
- First-pass settings groups exist; full CFW setting taxonomy is next

## Platform Foundation

- Replace `sysproxy` shelling with native proxy manager contract
- Define helper install/uninstall contract
- Define launchd bootstrap/bootout contract
- Define TUN runtime and NetworkExtension coordination contract
