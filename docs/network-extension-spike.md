# TUN / Network Extension / App Sandbox — Production Decision

**Status (0.3.1): closed decision, not an open “todo”.**

## Production TUN path (shipped)

```text
App (user) --control session--> cfw-helper (root, SMAppService)
                              --> clash-rs or mihomo (root utun)
```

This is the official Service Mode / TUN path for Clash for Mac on Apple Silicon.

## Network Extension

- Spike artifacts may remain under `macos/NetworkExtensionStub/` for research.
- **Not enabled, not bundled, not default, not advertised as done.**
- Revisit only if helper TUN becomes untenable on a future macOS — not for 0.3.1 marketing.

## App Sandbox

- **Rejected** for the main app while privileged root helper TUN is required.
- Full App Sandbox + root LaunchDaemon helper is a conflicting trust model for this product.
- Hardened Runtime + Developer ID + notarization remain the shipping security baseline.

## Exit criteria if NE is ever reconsidered

- [ ] arm64-only system extension builds and notarizes
- [ ] Parity with helper TUN (DNS hijack / routes)
- [ ] Explicit Sandbox redesign (likely drop root helper)
- [ ] Feature flag cutover with fallback

Until then, release notes must say: **helper TUN is production; NE/Sandbox are not.**
