# Clash for Mac — Release Gate

**Goal:** ship a distributable **Apple Silicon (arm64) only** beta that real users can install without Gatekeeper fights, and that covers CFW 0.20.39's core daily path.

**Hard platform rule:** never support Intel Mac / Universal Binary. Builds and CI must refuse `x86_64-apple-darwin` and lipo.

## Done when all of these are true

1. **Build**
   - `./scripts/assert_apple_silicon.sh` passes
   - `cargo test --workspace` passes on `aarch64-apple-darwin`
   - `cargo tauri build` produces `Clash for Mac.app` with:
     - `Contents/MacOS/clash-for-mac`
     - bundled `resources/cores/clash-rs` (default Rust core)
     - bundled `resources/cores/clash-darwin` (mihomo fallback)
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
   - Version ≥ `0.3.1` with CHANGELOG entry that does **not** claim unfinished work
   - LICENSE present (MIT per Cargo.toml)
   - CI: test on push/PR; `cfw-perf-gate` records metrics without claiming 「3×」 without baseline
   - `docs/parity-checklist.md` matches reality (no stale unchecked items that are already done)

5. **Explicit product decisions (closed — do not reopen as “missing features”)**
   - Pixel-perfect screenshot parity vs CFW *(optional polish)*
   - Proven 3× performance vs CFW *(metrics recorded; claim forbidden without baseline)*
   - SSID policy, Monaco editor, DHCP server, full PAC editor *(deferred polish)*
   - Sparkle *(cancelled — `tauri-plugin-updater`)*
   - Universal Binary / Intel Mac *(permanently unsupported)*
   - Network Extension / full App Sandbox *(rejected as production path — helper TUN is official)*
   - React as product UI *(rejected — Tauri WebKit UI is official; React ≠ stronger than Tauri)*
   - Default core is **clash-rs**; mihomo is fallback only



## Gate beta4 regression (macOS 27 `26A5388g`)

Run on the Golden Gate beta4 machine after dependency successors land:

1. `rustc -V` shows **1.97.1**; `cargo test --workspace` green
2. Service Mode Install → Login Items approve → TUN on/off (no ghost toggle)
3. System Proxy on/off via **SCPreferences** path; quit restores snapshot
4. Subscription update + GeoIP download (reqwest 0.13 / rustls platform-verifier)
5. Profile mixin / parser YAML round-trip (noyalib compat Value DOM)
6. Notarization staple: briefly **disable system proxy** first — CloudKit/staple can hang otherwise

```bash
sw_vers
rustc -V
cargo test --workspace
npm --prefix apps/cfw-tauri-shell run build
```

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
- [x] Editable PAC script UI + Use PAC Script (macOS Auto Proxy URL)
- [x] Connections Show Process column
- [x] Tray delay title + tooltip sync
- [x] Providers / Rules in primary nav
- [x] Pinned mihomo v1.19.28 + GeoIP metadb SHA-256

### P2 — polish (not blocking beta)
- [ ] Update-all cancel mid-flight
- [ ] Shortcut capture UI / full CFW settings migration

### P3 — explicitly deferred / rejected
- Screenshot parity, proven 3× CFW gates (without baseline), SSID, Monaco diff, DHCP, proxied terminal, child-process log tail
- Sparkle auto-update *(rejected — tauri-plugin-updater)*
- Universal Binary / Intel *(rejected — Apple Silicon only)*
- MaxMind license-key download path (URL update works; CFW token→tarball path not ported)

### 0.3.1 notes
- Default core cutover: **clash-rs**; mihomo fallback only
- Tauri WebKit UI remains product UI (React migration rejected)
- Helper TUN is production; NE / App Sandbox rejected as production path
- Do not advertise 「3× CFW」 without same-machine baseline JSON

