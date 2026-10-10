# Build 40063: superseded after cross-generation liveness failure

Build 40063 was signed, notarized and installed from
`8f01431793ec1c41a7d8daf16912d52dfd68af38`. Preserve its frozen source,
signed application, Apple transaction and installation evidence under
`target/release-worktrees/40063` and
`/Users/bill/cfw-release-history/native-wire-install-40063-20260915/`.

Installed checks passed Off-mode latency, independent local proxy traffic,
editable runtime ports, global shortcut dispatch and automatic local startup.
Stopping that automatic session exposed a quarantined Authority and rejected
stopped attestation. The liveness supervisor retained deadlines and heartbeat
timestamps across owner generations. Its timer could observe a new core state
before the XPC handler replaced the supervisor's old timestamp, prematurely
revoking or quarantining the new owner.

Deterministic regressions reproduce both races in the old implementation.
40064 moves heartbeat seeding, authenticated renewal, timeout checks and stop
deadline enforcement under the Authority core's state lock. It removes the
duplicate supervisor clocks. New owner generations receive a fresh heartbeat
window, while retries and heartbeats cannot extend a committed stop deadline.
The five-second timeout, owner authentication and exact Off proof remain intact.

Final linked-native regression passed 675 tests. This is source evidence;
40064 installation, repeated lifecycle operations and standalone network
acceptance remain to be collected. The old installed quarantine is not an Off
proof. Preserve its journal and use the existing authenticated recovery path.

This consumed candidate requires replacement because native product bytes
change, not because a test or collector failed. No 40063 receipt is relabelled
as 40064 evidence. Preserve user profiles, credentials, settings and CFW.
