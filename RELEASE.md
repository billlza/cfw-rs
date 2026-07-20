# Clash for Mac — Release Gate

**Goal:** ship a distributable Apple Silicon beta that real users can install without Gatekeeper fights, and that covers CFW 0.20.39's core daily path.

## Done when all of these are true

1. **Build**
   - `cargo test --workspace` passes on `aarch64-apple-darwin`
   - `cargo tauri build` produces `Clash for Mac.app` with:
     - `Contents/MacOS/clash-for-mac`
     - bundled `resources/cores/clash-darwin`
     - bundled `resources/helpers/cfw-helper`
     - `Contents/Library/LaunchDaemons/com.bill.clashformac.helper.plist` (via `scripts/bundle_service_mode.sh`)

2. **Sign & distribute**
   - App and nested binaries signed with Developer ID (`YKUPL7Z869`) + hardened runtime
   - `codesign --verify --strict` passes
   - Notarization + staple documented; run when Apple credentials available
   - DMG (or zip) install instructions in README

3. **Core product path (no fake success)**
   - Start/stop mihomo core from the app
   - Import remote profile URL → apply → proxy groups live from controller
   - System Proxy on/off with snapshot restore on quit
   - Service Mode / TUN either works after Login Items approval, or fails with an actionable error (never silent no-op)
   - Tray + `clash://install-config` deep link work

4. **Ship hygiene**
   - Version ≥ `0.1.0` with CHANGELOG entry
   - LICENSE present (MIT per Cargo.toml)
   - CI: test on push/PR; release build documented or automated
   - `docs/parity-checklist.md` matches reality (no stale unchecked items that are already done)

5. **Explicitly out of scope for this beta (tracked, not blocking)**
   - Pixel-perfect screenshot parity vs CFW
   - Proven 3× performance CI gates
   - SSID policy, Monaco editor, DHCP server, full PAC editor
   - In-app Sparkle auto-update

## Verification commands

```bash
cargo test --workspace
scripts/fetch_core.sh
scripts/build_helper_resource.sh
SKIP_BUILD=0 scripts/bundle_service_mode.sh
codesign --verify --strict --verbose=2 "target/release/bundle/macos/Clash for Mac.app"
```

## Build status (2026-07-20)

- [x] `cargo test --workspace` green
- [x] Release `.app` produced (`target/release/bundle/macos/Clash for Mac.app`)
- [x] Bundled `clash-darwin` + `cfw-helper` + LaunchDaemon plist
- [x] Developer ID signature verifies with Apple secure timestamp
- [x] Zip archive at `target/release/bundle/dmg/Clash for Mac_0.1.0_aarch64.zip`
- [x] Notarization + staple (Accepted 5192d93c-00c0-457a-8f35-1708ebb265a7)
- [x] Default `profile.store-selected` + log folder reveal/copy
- [x] Rebuild + sign with entitlements (in notarized 0.1.0 artifacts)
- [ ] Clean-machine install smoke (user: copy to /Applications, approve Login Item, toggle TUN)

## Distributable artifacts (0.1.0)

- `target/release/bundle/macos/Clash for Mac.app` — Notarized Developer ID + staple
- `target/release/bundle/dmg/Clash for Mac_0.1.0_aarch64.dmg` — stapled
- `target/release/bundle/dmg/Clash for Mac_0.1.0_aarch64.zip` — from stapled app

To reproduce a notarization-ready build on your Mac:

```bash
cd ~/cfw-rs
SKIP_BUILD=1 ./scripts/bundle_service_mode.sh   # uses Apple timestamp by default
./scripts/make_dmg.sh
xcrun notarytool submit "target/release/bundle/dmg/Clash for Mac_0.1.0_aarch64.dmg" \
  --keychain-profile AC_PASSWORD --wait
xcrun stapler staple "target/release/bundle/macos/Clash for Mac.app"
xcrun stapler staple "target/release/bundle/dmg/Clash for Mac_0.1.0_aarch64.dmg"
```

## Remaining backlog (post-0.1.0 beta)

### P0 — remaining for confidence (not blocking GitHub Release)
- [ ] Clean-machine smoke: /Applications install, Login Items approve, TUN toggle

### P1 — done in 0.1.0
- [x] Default `profile.store-selected: true`
- [x] Logs: Copy + Open Folder (`reveal_logs_directory`)
- [x] macOS `entitlements.plist` (network client/server) wired into sign script
- [x] Quality panel no longer claims proven 3× speedup
- [x] `.cursor/` gitignored; broken `sign_and_dmg.command` removed
- [x] Editable system-proxy bypass list (Settings textarea → `networksetup`)
- [x] GeoIP status/update (no `Unknown` placeholder)
- [x] Honesty pass: version badge `0.1.0`, TUN=`SmAppServiceRootHelper`, Service Mode Manage→SMAppService, delay URL editable, Show Process/PAC labeled deferred

### P2 — polish (not blocking beta)
- [ ] Tray delay **icon** visual sync (tooltip works when `show_tray_proxy_delay_indicator`)
- [ ] Editable PAC script UI (bypass list is done; PAC editor still missing)
- [ ] Update-all cancel mid-flight
- [ ] Shortcut capture UI / full CFW settings migration
- [ ] Connection process-path column

### P3 — explicitly deferred
- Screenshot parity, 3× CI gates, SSID, Monaco diff, DHCP, Sparkle auto-update, proxied terminal, child-process log tail
- MaxMind license-key download path (URL update works; CFW token→tarball path not ported)

