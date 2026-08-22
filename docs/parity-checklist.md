# macOS 15 network-stack readiness checklist

This checklist tracks the rewritten product contract. Checked source or unit
test items do not imply a signed physical-device release.

## Implemented in source

- [x] arm64-only Cargo and Xcode build guards
- [x] macOS 15 deployment target in native and Tauri configuration
- [x] retired root TUN/service-mode starts fail closed
- [x] one-way legacy helper/control-session tombstone
- [x] typed engine modes, states, events, snapshots, and domain errors
- [x] serialized bounded application coordinator with Off-mediated switching
- [x] deterministic validated sing-box Proxy/Tunnel projections for the
      closed direct/block/Shadowsocks/VMess/VLESS-Reality/Trojan/Hysteria2/
      AnyTLS/TUIC-v5 schema, with secret-free credential slots
- [x] Rust `NativeFrameworkBridge` C ABI wired into the production application
- [x] source-built sing-box `v1.13.15` plus digest-pinned security, raw-packet,
      DNS, and endpoint-conflict patches linked into ProxyAgent and Packet Tunnel
- [x] Swift 6 Host Bridge, `SMAppService` registration, System Extension and
      Network Extension control paths, and public bounded packet pump
- [x] root-context Global Authority with one durable global lease, hash-chained
      recovery journal, exact Host/ProxyAgent/Provider role-scoped XPC,
      heartbeat/revocation events, and truthful stop/Off reconciliation
- [x] bounded Authority journal generation compaction with hash-chained
      checkpoints, a seven-record lifecycle finish reserve, active/previous
      generation retention, and fault-injected commit/cleanup crash recovery
- [x] transactional authorized SCPreferences apply, effective-state
      verification, conflict-aware restore, and typed authorization failures
- [x] ticket-only Tunnel configuration/secret redemption and capability-only
      System Proxy ownership, with no App Group cross-context fallback
- [x] deterministic/unit coverage for Global Authority recovery, liveness,
      fast-user-switch revocation, owner interruption, replay, secret erasure,
      and lifecycle races
- [x] old Clash YAML runtime configuration, REST/WS, scripts, PAC, core
      installer, external runtime, and controller removed from the product
      graph; Clash Meta YAML survives only as a converted subscription import
      syntax at the validation boundary
- [x] strict Tauri CSP and no global Tauri JavaScript injection
- [x] source/build dependency pins, offline libbox build, native-product graph,
      production-boundary, Authority-ordering, notary-log, Gatekeeper-state,
      and final-candidate schema v3 fail-closed gates, including the PS256
      physical aggregate to physical-candidate manifest cross-binding
- [x] controller snapshots, proxy selection/delay, rules, connection/log streams,
      connection close, DNS query, and cache flush use real typed commands;
      pinned-engine provider management is explicitly unsupported rather than
      represented by fabricated empty success
- [x] GPL-3.0-or-later workspace license

## Must be completed before release

- [ ] verify old job/root process/ports/routes/DNS are absent after migration
- [ ] build the exact candidate with matching Host, ProxyAgent, Packet Tunnel,
      App Group, Keychain, Network Extension, and System Extension Developer ID
      provisioning; prove every nested identity and entitlement after install
- [ ] prove role-scoped Global Authority XPC admission/rejection and real
      Host/ProxyAgent/Provider liveness under the installed signed identities
- [ ] prove immutable shared-Keychain entry, missing-only provisioning,
      in-memory slot injection, and revision-bound cleanup under those installed
      Host/ProxyAgent entitlements
- [ ] complete signed installation, approval/denial, upgrade/replacement,
      downgrade, fast-user-switch, reboot, and uninstall tests on macOS 15 and
      current macOS
- [ ] prove Host, Global Authority, ProxyAgent, and Provider crash/connection-loss
      recovery reaches exact Off or explicit Quarantined without stale ownership
- [ ] prove non-interactive System Proxy restore after Authorization Services
      rights expire, or introduce and validate a narrowly scoped privileged
      SystemConfiguration boundary
- [ ] pass IPv4/IPv6/TCP/UDP/QUIC/DNS/route packet evidence
- [ ] pass weak-network, resource, 100-switch, and operator-observed 3-hour-per-OS internal-release soak gates
- [ ] pass nested signing, entitlement, provisioning, notarization, staple, and
      Gatekeeper gates with assessments enabled for the unchanged candidate
- [ ] publish complete corresponding source, modification notice, SBOM, and
      source/binary hashes with the release
- [ ] regenerate and legally approve the merged release SBOM, third-party
      notices, blocker report, and corresponding-source closure for the exact
      signed bundle, then verify the public artifacts and URLs

No unchecked release item may be replaced by a VPN status, interface-presence,
CI-green, unsigned build, simulator, or locally generated artifact claim.
