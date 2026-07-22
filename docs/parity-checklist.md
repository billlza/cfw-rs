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
      closed direct/block/Shadowsocks/VMess/VLESS-Reality/Trojan/Hysteria2
      schema, with secret-free credential slots
- [x] Rust Apple-network adapter boundary with explicit missing-native failure
- [x] Swift 6 Host Bridge, shared protocol, Agent, System Extension, and public
      bounded packet-pump foundation
- [x] transactional SCPreferences apply, effective-state verification, and
      conflict-aware restore
- [x] old Clash YAML, REST/WS, scripts, PAC, core installer, external runtime,
      and controller removed from the product graph
- [x] strict Tauri CSP and no global Tauri JavaScript injection
- [x] source/build dependency pins and offline libbox build gate
- [x] GPL-3.0-or-later workspace license

## Must be completed before release

- [ ] verify old job/root process/ports/routes/DNS are absent after migration
- [ ] link the pinned source-built libbox into ProxyAgent and Packet Tunnel
- [ ] replace the system extension's blocked state transport with authenticated
      global XPC, root-owned replay state, and multi-user engine arbitration
- [ ] prove the public packet contract; no private file-descriptor access
- [ ] connect the Rust coordinator to the signed Swift Host Bridge
- [ ] prove immutable shared-Keychain entry, missing-only provisioning,
      in-memory slot injection, and revision-bound cleanup under the installed
      dedicated Host/ProxyAgent entitlement
- [ ] complete signed installation/approval/upgrade/downgrade/multi-user/uninstall
      tests on macOS 15 and current macOS
- [ ] pass IPv4/IPv6/TCP/UDP/QUIC/DNS/route packet evidence
- [ ] pass weak-network, resource, 100-switch, and 24-hour soak gates
- [ ] pass nested signing, entitlement, provisioning, notarization, staple, and
      Gatekeeper gates
- [ ] publish complete corresponding source, modification notice, SBOM, and
      source/binary hashes with the release
- [ ] generate and validate the merged release SBOM and third-party license
      report against the signed bundle

No unchecked release item may be replaced by a VPN status, interface-presence,
CI-green, unsigned build, simulator, or locally generated artifact claim.
