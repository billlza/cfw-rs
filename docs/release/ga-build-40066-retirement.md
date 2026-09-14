# Build 40066: native acknowledgement of completed stops

Build 40066 from `1354bef080cb269d966f6083612887e0606a6d3f` completed signing
and notarization, but was not installed. Preserve its frozen source and signed
application under `target/release-worktrees/40066`. Its notarization submission
is `3cb35bfd-e64d-4132-bd31-9b9022354c35`; the original operator history is
`/Users/bill/cfw-release-history/off-reconciliation-install-40066-20260915/`.

The coordinator fix consumes a successful authoritative native Off observation.
Further native-boundary tests exposed the complementary case: Stop still
rejected a released owner when the caller had not consumed that final status,
or another status read had already completed the native barrier. This matters
after an intervening observation failure and for explicit Stop or shutdown.
`native-released-stop-red-v1.log` reproduces IdentityRejected both with and
without a prior final status read. These are native integration regressions;
40066 has no installed-network acceptance claim.

40067 keeps active-owner Stop ordering unchanged. For an owner already observed
at stable Off, it checks an exact persisted Stopping context when present,
executes the existing independent global Off query/recovery, and requires an
authenticated Off replay cursor matching installation, epoch and generation.
Only then does it acknowledge the completed stop without issuing another owner
teardown. Missing owner proof, a different generation, an active lease, failed
observations and absent cursor evidence are rejected. No public RPC, credential
input, permission change or weaker authentication is introduced.

The full native suite passed 680 tests with the actual linked Libbox runtime.
Coverage includes all three native owner modes, both status-observation orders,
wrong contexts, missing owner proof, restarted-Authority recovery, and the exact
durable cursor checks. The first expanded run had two invalid local-mode test
fixtures; the fixture request mode was corrected, and the failed log is retained.
Successor installed tests remain required before delivery.

The installed predecessor is still 40065. Installing 40067 must replace that
actual verified application, not pretend that 40066 was installed. Its profiles,
credentials, recovery history and the current CFW backup network are preserved.
