# Clash for Mac (`cfw-rs`)

**Apple Silicon only** rebuild of Clash for Windows (CFW `0.20.39`) for macOS.

- **Platform: `aarch64-apple-darwin` / macOS 13+ only** — Intel Mac and Universal Binary are **never** supported
- Shell: Tauri 2 + WebKit (`apps/cfw-tauri-shell/ui/`) — this is the product UI (React is not a replacement for Tauri)
- **Core (default): clash-rs (Rust)** — mihomo remains automatic fallback
- **Updates:** App menu **Check for Update…** + in-app badge when a newer GitHub release exists
- **Measured bench:** General → Core Bench shows clash-rs vs mihomo cold-start / API / weak-net results (`scripts/kernel_compare.py`)
- Privileged TUN: SMAppService helper (**production**). Network Extension / App Sandbox are **not** the production path
- Updates transport: `tauri-plugin-updater` (Sparkle is not used)

Release gate: [`RELEASE.md`](./RELEASE.md) · Parity: [`docs/parity-checklist.md`](./docs/parity-checklist.md) · Changes: [`CHANGELOG.md`](./CHANGELOG.md)

## Why this is stronger than CFW (without fake 「3×」)

| Area | CFW 0.20.39 | Clash for Mac |
|------|-------------|----------------|
| Shell | Electron | Tauri 2 (native WebKit) |
| Core | mihomo (Go) | **clash-rs (Rust) default** + mihomo fallback |
| CPU | often Universal / broader | **arm64-only**, tuned for Apple Silicon |
| TUN | helper/service | SMAppService root helper (typed Rust boundary) |
| 「3×」claim | marketing | **Not claimed** until same-machine baseline exists |

## Product decisions (closed)

| Topic | Decision |
|-------|----------|
| React UI rewrite | **Rejected** — React is a page framework, not stronger than Tauri; keep WebKit UI |
| Network Extension | **Not production** — helper TUN stays official ([decision](./docs/network-extension-spike.md)) |
| App Sandbox | **Rejected** while root helper TUN is required |
| Universal Binary / Intel | **Permanently rejected** |

## Install (signed beta · Apple Silicon)

1. Download `Clash for Mac_*_aarch64.dmg` (or `.zip`) from the [GitHub Releases](https://github.com/billlza/cfw-rs/releases) page.
2. Open the DMG and drag **Clash for Mac** into `/Applications`.
3. Launch once. If macOS prompts, use **Open** (app is Developer ID + notarized).
4. Before enabling **TUN / Service Mode**, approve the helper under **System Settings → General → Login Items & Extensions**.

Local rebuild / resign (maintainers): see [`RELEASE.md`](./RELEASE.md).

## Develop

```bash
./scripts/assert_apple_silicon.sh
./scripts/fetch_clash_rs.sh   # default core
./scripts/fetch_core.sh       # mihomo fallback binary

cargo test --workspace
cargo run -p cfw-tauri-shell
```

## Workspace

| Path | Role |
|------|------|
| `apps/cfw-tauri-shell` | Desktop app (`clash-for-mac`) |
| `apps/cfw-cli` | Headless / debug CLI |
| `crates/cfw-core` | Domain + settings |
| `crates/cfw-controller` | Clash REST/WS client |
| `crates/cfw-runtime` | Core process + clash-rs / mihomo install |
| `crates/cfw-profiles` | Profile import/apply/mixin |
| `crates/cfw-platform` | sysproxy / launchd / SMAppService / TUN |
| `crates/cfw-helper` | Privileged helper binary |

## License

MIT — see [`LICENSE`](./LICENSE).
