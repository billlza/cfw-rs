# GA build 40046 retirement

Build 40046 is classified as
`retired_product_change_after_install_before_ga_runtime_acceptance`.
It completed application and DMG notarization, both package sets and the
40045 -> 40046 installation. It did not complete GA runtime acceptance or
public release.

Its native Xcode target linked the Objective-C adapter archive without making
the adapter module importable by Swift. Conditional compilation therefore
omitted the real libbox service implementation and selected `libboxUnavailable`.
The original factory failure was reproduced before reading any profile,
credential or system proxy state. CFW coexistence is not its cause.

Build 40047 includes the adapter module, requires the linked runtime at compile
time, corrects the previously excluded implementation's protocol and callback
boundaries, and makes failed startup switches reflect observed native state.
It also carries the profile source/name display correction, independent network
switches, typed selector/rule imports, offline policy views, and bounded process
owner lookup through public macOS APIs. These changes alter
application bytes, so recovery of 40046 cannot deliver them.

Preserve the frozen `target/release-worktrees/40046` checkout, signed app,
packages, Apple receipts, installation journals and backups. Its notarized tree
`49f6b28e70b5e3bde5d86179f0c47a8e2e2ce29bca69c04b7d160d852f448e22`
is the supported predecessor for installing 40047; it is not new acceptance
evidence. No signing or publication gate is relaxed by allocating the successor.

The immediate delivery is an installed package for smoke testing and user
feedback. Public release still requires its own real runtime acceptance.
The baseline defects, source corrections and remaining import gaps are documented in
[`cfw-compatibility-audit.md`](../cfw-compatibility-audit.md).
