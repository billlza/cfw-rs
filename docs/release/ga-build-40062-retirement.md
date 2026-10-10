# Build 40062: superseded after installed native command failures

Build 40062 completed signing, notarization and installation from
`7c9e83feed4ab6c62efea60796f15a8b2dc0e0e7`. Its frozen source, application,
Apple transaction and installation records remain intact under
`target/release-worktrees/40062` and
`/Users/bill/cfw-release-history/client-parity-install-40062-20260914/`.

Installed acceptance reproduced two protocol failures: Off-mode latency's new
target/status fields were rejected by the complete NativeBridge envelope, and
Local Proxy's valid owner capability was rejected by a System Proxy-only wire
guard. A failed preparation also lost its exact failed-start cleanup transaction,
leaving the host unable to acknowledge an independently proven Off state.
Review found the same mode omission in orphaned service retirement. A separate
installed UI check reproduced input focus loss after the first search character.

40063 changes those product paths. It keeps strict field/type validation,
capability binding, exact-generation cleanup, independent Off proof and the
existing orphaned-service network/process boundaries. It retains editor focus
and defers refresh during text composition. Each changed failure path has a
regression; component results remain distinct from installed network acceptance.

This allocation is required by changed product bytes in a consumed candidate.
Collector, documentation or test changes alone do not require retirement. No
40062 receipt is deleted, rewritten or used as proof for 40063. The replacement
preserves profiles, Keychain entries, settings, recovery journals and CFW.
