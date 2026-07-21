# Clash for Mac (`cfw-rs`)

Apple Silicon–only rebuild of Clash for Windows (CFW `0.20.39`) for macOS.

- Target: `aarch64-apple-darwin` / macOS 13+
- Shell: Tauri 2 + WebKit UI
- Core: pinned mihomo (`clash-darwin`)
- Privileged path: SMAppService helper for Service Mode / TUN

Release gate: [`RELEASE.md`](./RELEASE.md) · Parity: [`docs/parity-checklist.md`](./docs/parity-checklist.md) · Changes: [`CHANGELOG.md`](./CHANGELOG.md)

## Install (signed beta · Apple Silicon)

1. Download `Clash for Mac_0.2.0_aarch64.dmg` (or `.zip`) from the [GitHub Releases](https://github.com/billlza/cfw-rs/releases) page.
2. Open the DMG and drag **Clash for Mac** into `/Applications`.
3. Launch once. If macOS prompts, use **Open** (app is Developer ID + notarized).
4. Before enabling **TUN / Service Mode**, approve the helper under **System Settings → General → Login Items & Extensions**.

Local rebuild / resign (maintainers): see [`RELEASE.md`](./RELEASE.md).

## Develop

```bash
cargo test --workspace
cargo run -p cfw-tauri-shell
# or:
cargo tauri dev --manifest-path apps/cfw-tauri-shell/Cargo.toml
```

## Workspace

| Path | Role |
|------|------|
| `apps/cfw-tauri-shell` | Desktop app (`clash-for-mac`) |
| `apps/cfw-cli` | Headless / debug CLI |
| `crates/cfw-core` | Domain + settings |
| `crates/cfw-controller` | Clash REST/WS client |
| `crates/cfw-runtime` | Core process + mihomo install |
| `crates/cfw-profiles` | Profile import/apply/mixin |
| `crates/cfw-platform` | sysproxy / launchd / SMAppService / TUN |
| `crates/cfw-helper` | Privileged helper binary |

## License

MIT — see [`LICENSE`](./LICENSE).
