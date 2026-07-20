# macOS Platform Foundation

The Rust platform boundary for the rebuild lives in
[`crates/cfw-platform`](/Users/bill/cfw-rs/crates/cfw-platform/src/lib.rs).

## Interfaces

- `SystemProxyService`
  - read current state
  - set proxy mode against a concrete port
  - restore original proxy snapshot on exit/failure
- `HelperService`
  - install and uninstall privileged helper runtime
- `LaunchdService`
  - bootstrap and bootout typed jobs
- `TunService`
  - install TUN runtime
  - start and stop TUN lifecycle

## Current Decisions

- Target: `MacOsArm64`
- Minimum macOS: `13.0`
- System proxy strategy:
  native `SystemConfiguration`-style manager with explicit snapshot/restore
- Helper strategy:
  keep privileged operations outside the UI shell
- launchd strategy:
  typed contract, no ad-hoc product-layer shell scripts
- TUN strategy:
  **current:** privileged helper via `SMAppService` + root helper for TUN
  (`SmAppServiceRootHelper`). **long-term optional:** `NetworkExtension`
  packet tunnel — not the shipping path for 0.1.x.

## Why This Matters

This keeps the rebuild aligned with user-visible CFW behavior while avoiding
hard-coded legacy implementation details such as:

- Electron-owned privileged flows
- Intel-specific binary selection
- hidden platform shell-outs as the primary source of truth

