# cfw-rs

`cfw-rs` is an Apple Silicon-only rebuild of Clash for Windows for macOS.

This workspace is organized around a very deliberate constraint set:

- Target only `aarch64-apple-darwin`
- Rebuild the original product behavior and information architecture first
- Move privileged macOS operations out of the UI shell
- Keep platform glue thin so core behavior remains testable and replaceable

## Why This Layout

The original macOS build bundles four distinct responsibilities into one app:

1. UI shell and tray/menu behavior
2. Core process orchestration
3. System proxy / helper / privilege flow
4. Settings and profile lifecycle

That coupling made the product easy to ship, but it also made long-term
maintenance brittle. This workspace separates those boundaries up front.

## Workspace

- `apps/cfw-tauri-shell`
  Thin desktop shell. This is where the Apple Silicon-only desktop app will
  live. The recommended implementation is a Rust-first Tauri 2 shell with a
  WebKit-backed UI for high visual fidelity.
- `crates/cfw-core`
  Product domain and orchestration model: profiles, proxies, modes, settings,
  controller state, and helper command contracts.
- `crates/cfw-platform`
  Platform integration boundary. This crate should expose traits and macOS
  implementations for proxy control, launchd helper install, and app lifecycle
  integration.
- `crates/cfw-helper`
  Privileged helper binary boundary for root-required actions such as service
  install, launchd registration, and network helper lifecycle.

## Product Scope

The rebuild target is not "a Clash GUI for macOS" in the abstract. It is a
behaviorally compatible replacement for the final `0.20.39` Apple Silicon CFW
experience, with modernized internals and explicit removal of Intel support.

Current reverse-engineering findings are tracked in
[`docs/architecture.md`](./docs/architecture.md).

