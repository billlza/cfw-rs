# Build 40051 disconnected proxy controls correction

40051 completed signing, notarization and local installation. Its frozen source,
application and receipts remain unchanged. No public release completed.

User testing exposed a missing workflow: latency testing required an active
System Proxy/TUN controller, and the locator read the empty live group list
while the page displayed saved groups. The header also included an extra diamond
absent from the installed CFW 0.20.39 toolbar. The native request shape checker
also omitted the two System Proxy authorization opcodes accepted by the typed
dispatcher, so actual bridge requests could fail before showing authorization.

40052 uses the same displayed group for rendering, selection location and latency
targets. It removes the extra diamond and filters timed-out nodes per group.
Disconnected measurements use the pinned libbox protocol dialers and HTTPS URL
test in a bounded transient Box. No inbound, controller, TUN interface, system
proxy setting, route policy or persistent cache is created. Credentials retain
their existing native vault binding; Go receives only the resolved in-memory
configuration. The host/bridge protocol advances to v9; persisted engine-owner
and Authority schemas are unchanged. The request shape checker now switches on
the same typed opcode enum, so omitted cases fail compilation. Both authorization
commands are tested through the serialized bridge entrypoint.

Cancellation stops subsequent batches, visibly waits for the bounded in-flight
batch, and discards its reply. Profile/engine changes invalidate old results.
Completed measurements survive a saved selector change in the same profile.

Validation includes UI handler regressions, native transport/ownership tests,
projection and wire checks, and real HTTP CONNECT plus verified HTTPS sockets.
The source-built SDK also measured both existing SOCKS5 nodes while leaving the
machine's system proxy observation unchanged. CFW remained running for that test;
this does not establish acceptance with CFW shut down.

The application and libbox bytes change, so 40051 is recorded as
`retired_product_change_after_install_before_ga_runtime_acceptance` and 40052 is
the successor. Existing candidates and external notarization identities are
retained.
