# Changelog

## 0.4.0 - Unreleased

### Safety and migration

- Retire the privileged helper, external Clash-compatible cores, remote core
  installation, scripts, and PAC execution as runtime paths.
- Replace the old helper with a one-release, non-operational tombstone descriptor that can only
  stop, verify, clean, and unregister legacy state; it can never start a core.
- Remove automatic first-launch retirement. Startup leaves the existing VPN
  untouched, permits replacement profiles to be staged in a physically
  separate repository; the app performs the verified false-first retirement transaction only after explicit user
  confirmation plus a fail-closed native/profile cutover preflight.
- Block every new network mode until legacy helper/session/process state is
  gone and legacy System Proxy and DNS state has been explicitly verified.
  Ambiguous proxy or DNS ownership requires user review instead of an
  automatic overwrite.

### Network architecture

- Add typed engine API, sing-box configuration, application coordinator, and
  Apple-network adapter crates with Off-mediated Proxy/Tunnel switching.
- Add the macOS 15+, arm64 Swift protocol, ProxyAgent, Packet Tunnel System
  Extension, and bounded public `NEPacketTunnelFlow` packet-pump foundation.
- Wire the production Rust `NativeFrameworkBridge`, source-built libbox
  factories in ProxyAgent and Packet Tunnel, and root-context Global Authority
  through exact role-scoped XPC admission. Missing identity, capability,
  ticket, profile, or readiness evidence fails closed; the old helper, a
  downloaded core, private packet-flow APIs, user App Group state, and Data
  Protection Keychain access from the System Extension are not fallbacks.
- Compact the bounded Authority journal before a prepare consumes its
  seven-record finish reserve. Compaction commits a hash-chained checkpoint to
  the next anchored generation, retains only active and previous generations,
  detects rollback, and is fault-tested at every commit and cleanup boundary.

### Configuration and interface

- Replace Clash YAML/REST/WebSocket configuration with a closed app profile
  schema that projects deterministically to native sing-box JSON.
- Add closed typed profile schemas for `direct`, `block`, Shadowsocks, VMess,
  VLESS/Reality, Trojan, and Hysteria2, plus optional `route.final`. Persistent
  profiles contain canonical `credential_ref` values only; raw credentials,
  subscriptions/remote resources, scripts, executable paths, and unknown
  fields are rejected. Runtime projection produces empty secret placeholders
  and closed native injection slots. References are immutable: retries must be
  byte-identical and secret rotation requires a new UUID and profile update.
- Add missing-only credential entry backed by an atomic shared-Keychain vault.
  Renderer and bridge buffers are redacted and zeroized, present references are
  never re-prompted, and explicit two-phase garbage collection deletes only
  revision-bound orphans after repository revalidation.
- Add a private, versioned, digest-bound selected-profile record. Proxy and
  Tunnel starts require that selected profile and fail on missing or stale
  selection instead of silently using DIRECT; Off remains independently
  available.
- Separate DNS roles in both engine modes: two bounded numeric direct resolvers
  are referenced only by remote proxy endpoint `domain_resolver`
  primary/fallback fields. All ordinary DNS and route-level resolution uses one
  of two certificate-verified DoH transports explicitly detoured through the
  selected outbound; Tunnel additionally hijacks packet-flow DNS into that
  path. The pinned source patch permits one bounded retry for transport failure
  or rejected response, never on cancellation; duplicate, loopback,
  link-local, documentation, and virtual-tunnel endpoints are rejected.
- Split the Tauri composition root, platform adapters, and profile repository
  into bounded modules; remove the parallel tracked UI bundle.
- Keep the 0.3.5 dashboard: the same status bar, sidebar, nine pages, liquid-glass
  menus and dialogs, rebuilt against the 0.4.0 command surface instead of being
  replaced. Every entry point whose command is retired is gone with the row,
  button, or menu item around it — Service Mode and the privileged helper,
  starting/stopping and installing cores, the kernel benchmark, the tray-script
  and child-process runners, and the IPv6 switch. Controls the product cannot
  honour are disabled and state the backend's own reason instead of appearing to
  work: LAN exposure, bind address, engine log level, profile mixin, GeoIP
  download, and host DNS restore. Values the 0.4.0 payloads no longer carry are
  reported as unavailable rather than invented, profile mutations are offered
  only while the engine is Off, and an active data plane is claimed only after the
  engine snapshot's runtime identity, generation, digest, and readiness agree.
- Restore the controller-backed read, query, and stream commands (proxy, rule,
  provider, connection, log, DNS, and version surfaces) as a bounded command
  module. Their client is built only from the running engine's app-owned
  loopback controller, never from settings or a profile; the per-run secret is
  redacted out of every returned error, event payload, and `Debug` rendering.
  With no ready engine they fail closed with the unreachable-controller error
  instead of probing an unknown listener.
- Restore the profile-text, subscription, runtime-configuration, engine-switch,
  and shell command surfaces as four bounded command modules. Subscriptions are
  fetched over bounded HTTPS only, validated into the closed profile schema, and
  projected for both modes before they can be stored; the subscription URL lives
  inside the integrity-checked profile envelope and never appears in a profile
  listing. Subscription import converts Clash Meta YAML `proxies` lists and
  node-URI bundles (`ss://`, `vmess://`, `vless://` including Reality,
  `trojan://`, `hysteria2://`) into that schema at the boundary with bounded,
  alias-rejecting parsers; extracted secrets go to the credential vault, never
  into the stored profile, and import errors identify positions and keys
  instead of echoing document content. The subscription request advertises a
  Clash Meta client so panels serve the modern protocol set. Requests the
  schema cannot honour — unsupported proxy types, disabled certificate
  verification, plugins, chaining, port hopping — fail the import instead of
  being dropped. The runtime-configuration preview redacts the app-owned
  controller secret and fails closed if it survives redaction.
- Express the System Proxy and TUN switches as engine-mode transitions through
  the single Authority-mediated transition path, so neither switch can write a
  system proxy, a DNS server, a route, or a network preference, and neither can
  stop the other mode's data plane. Switches that the projection cannot honour
  (LAN exposure, non-loopback bind address, engine log level, profile mixin) and
  requests to write host DNS or fetch a GeoIP database now fail closed with an
  explicit reason instead of being accepted and ignored. Legacy on-disk Clash
  for Windows profiles are reported, never bulk-converted; their subscriptions
  are re-imported from the live URL instead.
- Restore tray proxy-group switching, window, deep-link, and diagnostics
  helpers. Tray labels and menu ids are bounded and generated, so a controller
  response cannot inject a menu entry, and diagnostics reads
  SystemConfiguration only: the fields the retired `networksetup`, `scutil`, and
  `route` invocations supplied are reported as explicitly unavailable.

### Supply chain and release status

- Move the workspace to GPL-3.0-or-later and pin the arm64 macOS 15 release
  toolchain and source-built libbox inputs.
- Build libbox with `with_clash_api`. The patched tree enables the clash API
  whenever a platform log writer is installed and the daemon always installs
  one, so the previous artifact failed every engine start in the stub
  constructor. The pinned tag list is now itself a verified build input: the
  pinned-input gate fails closed when a tag the engine start path requires is
  missing.
- Seal Tauri CLI's complete offline Cargo registry before and after compilation
  while excluding only three validated Cargo runtime tracking/lock files from
  the private snapshot. The exact normalization helper is digest-bound into the
  build-input and final toolchain manifests, and fetch/install warnings block
  the bootstrap.
- Add fail-closed release documentation for nested signing, provisioning,
  notarization, SBOM/license evidence, real packet evidence, weak-network
  recovery, resource limits, and physical-device testing.
- Upgrade physical evidence to aggregate schema v5, receipt schema v3, proof
  schema v3, and trust-policy schema v3. The signed policy digest now binds the
  exact single-machine profile, preventing old receipts from being relabelled
  under the new aggregate marker. The only accepted collector signature
  is PS256 with a source-pinned RSA-PSS-3072 Cloud KMS HSM key version; every
  harness report and receipt binds that identity and the recomputed final
  artifact-hash manifest. Final-candidate schema v3 derives the binding from the
  reopened aggregate and rejects the former caller-only evidence declaration.
  The two fixed clean-OS runs now share one automatically observed physical-
  machine identity, use distinct sealed boot-environment digests, and retain
  independent nonces, receipts, reports, and raw archives. The blocking soak is
  an operator-observed three-hour interval with no reported crash per OS for
  this limited internal distribution; it is not a remote-liveness or public-GA
  endurance claim.
- Build XcodeGen from checksum-bound source with a digest-pinned
  installed-resource patch, isolated resolved-only SwiftPM state, a real project
  generation probe, debug-path stripping, and a complete tree-v2 manifest.
- Replace the generic updater runtime with a project-owned bounded metadata
  check and one-use authorization. Before use, it revalidates the exact
  canonical GitHub identity and opens the official DMG release page. The app
  no longer downloads, extracts, or swaps its own installed bundle, and does
  not replace that bundle in process.
- Rotate the updater artifact trust root for 0.4.0 after the 0.3.5 private key
  became unavailable. Existing 0.3.5 installations cannot authenticate the
  new release archive and must install 0.4.0 from its signed, notarized DMG;
  there is no unsigned or alternate-key fallback. The replacement public key
  is embedded in 0.4.0 and its private half remains outside the repository.
- Keep in-process replacement intentionally absent because the required
  verified `SMAppService` daemon re-registration transaction is not implemented
  yet; metadata or a browser handoff is never reported as installation.
- Release remains blocked until installed-identity proof for shared-Keychain
  provisioning and authenticated in-memory Tunnel injection, physical packet
  capture of the pinned resolver-failover behavior, exact Developer ID and
  provisioning, signed physical-device data-plane and recovery tests, and the
  complete legal/publication evidence set have passed.

## 0.3.5 — 2026-07-21

Updater download progress UI (fixes “stuck on Checking…” after Download & Install).

### Updater
- Separate phases: checking / downloading / installing (no longer misuse Checking for downloads)
- Live percent + progress bar via `cfw://update-progress`
- Ignore `update-available` events while a download is in flight
- Handle “no update available” install result instead of leaving the dialog busy forever


## 0.3.4 — 2026-07-21

Quieter live streams + connections/log Diagnostics fixes (so Check for Update from 0.3.3 can pick this up).

### Diagnostics
- clash-rs `/connections` ports accept **int or string** (stops `invalid type: integer` spam)
- Logs level filter: event delegation + stream-only patch so ALL/INFO/WARNING clicks are not eaten by full re-renders
- Proxy delay **Pending** styled on `cfw-node-card`; in-flight tests keep Pending across snapshot refreshes

### Live streams (WARNING noise)
- Transient controller disconnects (`Connection reset`, `error sending request`, WS protocol reset) reconnect **quietly** — no Diagnostics WARNING spam when TUN flaps `en0`
- Clean WS close / log-level restart no longer logged as errors
- Core `[TUN] default interface changed …` remapped to **INFO** (expected mihomo monitor noise)

### Updater
- Pack `app.tar.gz` with `COPYFILE_DISABLE=1` and reject AppleDouble `._*` entries (fixes `failed to unpack ._Clash for Mac.app`)

## 0.3.3 — 2026-07-21

TUN truthfulness + product About / update feedback + Proxies/profile recovery.

### TUN (fixed)
- Switch reflects **live handoff** (`tun.enable` + managed root core), not a stale disk flag
- Fresh launch defaults to **Off** unless Service Mode actually owns a TUN-capable core
- Service Mode always spawns **mihomo** for TUN (clash-rs controller-ready ≠ working utun)
- Handoff readiness uses **controller API + netstat** — unprivileged `lsof` cannot see root listeners
- Failed handoff scrub `cache.db` (root-owned) and wait for ports before restarting in-process core
- Helper `serve` processes an existing control session **immediately** (no 5s first-wait race)
- After TUN up: sync persisted **Rule/Global** mode; auto-escape **Global+DIRECT** blackhole (looked like “TUN broken”)
- Heartbeat 10s / stale 90s to reduce helper tearing down a live TUN session
- System Proxy toggles **never** mutate `tun_mode`; UI re-syncs TUN after proxy changes

### Proxies / Profiles
- Entering Proxies, TUN toggle, settings-changed, and profile switch all **re-fetch controller snapshot**
- Empty mode chrome hidden when controller has no groups; clearer empty copy
- Removed meaningless Profiles hover 4-icon bar (use card click + right-click menu)
- Profile switch rollback re-applies previous profile; `controller_snapshot` no longer fails wholly when connections lag
- `set_proxy_mode` persists `runtime_mode`; hot-reload failures are no longer silent success

### About / Check for Update
- App menu **About Clash for Mac** and **Check for Update…** open the native product card

## 0.3.2 — 2026-07-21

Update UX + measured clash-rs vs mihomo answers on Apple Silicon.

### Updates
- macOS app menu: **Check for Update…** under About Clash for Mac
- Startup silent check; General header shows **→ vX.Y.Z** when a newer release exists
- Confirm → download/install via `tauri-plugin-updater` (GitHub `latest.json`)

### Measured kernel compare (not docs-only)
- `scripts/kernel_compare.py` runs clash-rs and mihomo on high localhost ports
- Ships `resources/benchmarks/kernel-compare-latest.json` with cold-start, controller API, delay, and weak-timeout burst metrics
- General **Core Bench** row + Feedback panel show the measured speedup / reliability deltas
- This host’s run: **~1.27×** faster cold start & controller API vs mihomo; weak-net / delay success tied at 100% — **not** a CFW 「3×」 claim

## 0.3.1 — 2026-07-21

Apple Silicon–only hardening with a Rust core default. Version stays **0.3.1**.

### What is stronger than CFW / prior builds (verifiable)
- **Default core: clash-rs (Rust)** on arm64; mihomo kept only as automatic fallback
- **Tauri 2 native shell** (not Electron) — smaller process model than CFW’s Electron
- **Apple Silicon only** — no Intel / Universal Binary tax
- Typed sysproxy / DNS / Login Item / helper paths from earlier 0.2–0.3 work remain

### Explicit product decisions (not unfinished “todos”)
- **UI:** Tauri + WebKit (`ui/`) is the product UI. React is **not** stronger than Tauri and is **not** a migration target.
- **TUN:** SMAppService privileged helper is the **production** path. Network Extension is research-only, not shipped.
- **App Sandbox:** **Rejected** for the main app while root helper TUN is required (Sandbox and root helper conflict).
- **「3× CFW」:** Not advertised. Perf CI records metrics only (`claim_3x_cfw: false`) until a same-machine CFW baseline exists.

### Platform
- Docs/CI refuse `x86_64` / lipo (`scripts/assert_apple_silicon.sh`)
- Sparkle remains cancelled (`tauri-plugin-updater` since 0.2.0)

### Core
- `CoreKind` default = `clash_rs`
- Pinned clash-rs **v0.10.7** aarch64 (checksum-verified)
- `--compatibility` is opt-in via `CFW_CLASH_RS_COMPAT` (avoids first-boot GeoIP stall)
- Mihomo fallback on missing binary / start / controller readiness failure

## 0.3.0 — 2026-07-21

Delay-test correctness + TUN stability for Apple Silicon.

### Proxies / delay test
- Failed and timed-out probes show **Timeout** (no more **N/A**)
- After one full round, every tested node has a final state (no leftover **Pending**)
- Adaptive concurrency (`hardwareConcurrency`, clamped 4–16; drops to 2 when backgrounded)
- Visible nodes probed first; incremental delay label patching (no full-page flash per chunk)
- Cancel on group switch / leave Proxies / second click
- Network default-route changes mark delay badges stale

### TUN
- Launch reconcile: if `tun_mode` + Service Mode Enabled → full root handoff (not a half start)
- TUN owns core → config changes force helper respawn (hot reload skipped for utun/routes)
- Safer defaults: `stack: mixed`, `strict-route: true`, DNS hijack `any:53` + `[::]:53`
- TUN settings Save always re-applies runtime config when TUN is on

### Stack
- Continues 0.2.0 platform path (SCPreferences proxy/DNS, Login Item, updater)

### Not included in 0.3.0 (do not treat as shipped)
- Network Extension / App Sandbox / React UI migration
- mihomo rewrite or clash-rs default cutover *(cutover landed in 0.3.1)*
- Proven 「3× CFW」 CI gates
- Universal Binary (permanently rejected; Apple Silicon only)
- Sparkle (superseded by tauri-plugin-updater)

## 0.2.0 — 2026-07-21

Apple Silicon performance and platform hardening release (P0–P2).

### P0
- ControllerClient process-wide singleton / reqwest connection pool reuse
- cfw-helper control-session supervision is FSEvents/`notify` event-driven (5s heartbeat fallback; no fixed 500ms poll)

### P1
- Connections page incremental DOM patching (no full-page `innerHTML` on every WS tick)
- Silent Start uses `ActivationPolicy::Accessory` + Dock hide; tray Show restores Regular + Dock
- Start at Login uses `SMAppService::mainAppService` Login Item (migrates off user LaunchAgent)

### P2
- DNS set/restore via SCPreferences with `networksetup` fallback
- `tauri-plugin-updater` + GitHub Releases `latest.json` (arm64)

### Stack (carried from Unreleased)
- Rust **1.97.1**; YAML via noyalib `compat-serde-yaml`; reqwest **0.13**; Tauri **2.11.5**
- System Proxy SCPreferences path; UI `ui/src/` + esbuild

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
