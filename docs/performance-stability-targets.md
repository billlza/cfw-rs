# Network data-plane performance and stability gates

These gates apply to the signed macOS 15+ arm64 build using the public
`NEPacketTunnelFlow` adapter and the pinned source-built libbox. Localhost
controller probes, Network Extension status, interface existence, and synthetic
three-sample tests are not substitutes for real data-plane evidence.

## Performance

| Metric | Gate |
|---|---:|
| Connect latency | p95 no more than 5 seconds |
| Disconnect latency | p95 no more than 3 seconds |
| Packet adapter throughput | at least 90% of same-machine System Proxy/libbox baseline |
| Packet adapter added latency | no more than 10% versus that baseline |
| Active idle CPU | below 1% |
| Active RSS | no more than 120 MiB |
| 100 mode switches | RSS growth no more than 5 MiB; FD growth no more than 2 |
| Soak | at least 3 continuous hours per pinned OS, 5-minute heartbeats, 15-minute real traffic, and no DiagnosticReports/Unified Log crash delta |

Report sample count, machine model, OS build, power mode, raw observations,
p50/p95/p99, and the exact build/source identities. The fixed
`networkQuality -c -M 5` argv, complete output, and executable digest bind the
OS-owned workload; payload size, protocol selection, internal concurrency, or
warm-up behavior that the tool does not expose must not be invented as caller
metadata. A gate script must fail when a probe is unavailable or does not meet
its threshold.

The 3-hour threshold is scoped to the current small internal distribution. A
future public GA must raise this profile after a separate review; 24 hours per
OS remains the recommended public-release target rather than an Apple-mandated
duration.

For v0.4.0, two endpoint timestamps are not soak evidence. The raw sample
ledger requires 37 owner-bound heartbeats at a fixed five-minute cadence and 13
successful `networkQuality` traffic observations at a fixed fifteen-minute
cadence. Every entry binds wall and monotonic time, the signed Host operation,
generation, terminal mode, and the exact PID/start/code-signing process roster.
A before/after DiagnosticReports inventory and a covering Unified Log fault
query must have an empty delta. Missing intervals, clock disagreement, process
restart/PID reuse, mode or generation drift, traffic failure, or crash evidence
fails the run.

## Weak-network matrix

- 100 ms latency, 1% packet loss, 10 Mbps;
- 300 ms latency, 5% packet loss, 1 Mbps;
- complete 30-second outage.

After path restoration, recovery p95 must be no more than 10 seconds. There
must be no busy loop, unbounded queue, stale Active state, duplicate libbox
instance, leaked socket/FD, or silent packet drop. Queue admission and drop
metrics must be bounded and observable.

Weak-network collection has no privileged helper and accepts no operator-
supplied command or path. Before collection, the operator must manually stage
the three reviewed `.pf` files from
`scripts/physical_capture/performance_profiles/` at the fixed root-owned paths
under `/Library/Application Support/Clash for Mac/ReleaseEvidence/performance-profiles/`
with mode `0444`, then run `sudo -v` in a separate terminal. PF must already be
enabled by a host-owned service; the collector records `pfctl -s info` and
blocks when it is disabled instead of changing the machine-wide PF lifecycle.
The collector only uses fixed `sudo -n /usr/sbin/dnctl` and
`sudo -n /sbin/pfctl` argv vectors.
`scripts/physical_capture/collector.py` is the fixed production entry. Its
argparse surface exposes `initialize`, `collect`, `recover-performance`,
`finalize`, and `publish`, with lane choices `macos15` and `current-macos` and
an exact `adversarial|lifecycle|packet|performance` harness enum. It accepts no
executable, argv, session path, context path, or output path. The lane plus
bounded attempt enum `01..03` selects a source-owned private session below
`target/`; a later attempt is forbidden until its contiguous predecessor is
durably abandoned and the terminal journal binding uniquely reopens one
source-owned failure, failure-recovery, shaping-recovery, or journal-recovery
record. A shaping restart-recovery record uses the v3 contract: it binds the
archive root, exact archived context, shaping intent, pre-abandonment journal
tip/state/time, the shaping intent creation lower bound, a captured fixed
`sudo -n -v` preflight, a contiguous `01..N` sequence with `N <= 3`, and exactly
two fixed restore commands plus two fixed empty-state queries per profile. A
missing, copied, malformed, non-contiguous, or incomplete closure blocks the
next attempt. If the original transaction wrote
`shaping-restoration-failed.json`, its v2 record is also reopened canonically
and bound to the same archive root, context, shaping intent, collecting journal
tip, transaction/profile plan, fixed command outcomes, and cleanup result; the
restart-recovery chain must begin after that failure record. Initialization
archives the live-validated context and bounded enum/numeric performance
parameters at fixed paths inside that locked session. `collect` enforces the
source-owned lifecycle, adversarial, packet, performance order, writes one
immutable exact-byte checkpoint per completed producer, and freezes the raw
union only after all four checkpoints reopen successfully. SIGINT/SIGTERM
become cooperative cancellation. A normal failure is recorded and abandons the
run; an interrupted shaping WAL keeps the session recoverable, and the recovery
command executes every fixed restore/query step before forcing abandonment and
a fresh complete run. If the process exits after publishing a complete recovery
but before journaling abandonment, the next invocation strictly reopens that
complete record and binds it without executing another privileged attempt. A
strictly valid incomplete prefix alone may advance to its next bounded attempt;
malformed history blocks before any `sudo` command. At most three durable
restart-recovery attempts are allowed; incomplete restoration remains an
explicit external blocker.
`finalize` performs the journaled one-shot nonce and receipt transactions,
reopens the frozen observations, materializes and revalidates all four reports,
and binds the finalized run record. `publish` accepts only the two bounded
attempt IDs and publishes only after both fixed OS run records are finalized.
Every one of the 60 transactions records durable intent before mutation, then
apply, an exact effective-state query, the bounded impairment/outage interval,
restore, and a query equal to the original empty anchor/pipe state. Only then
does the fixed real-traffic probe measure recovery. Cancellation still runs the
fixed restore path. An interrupted or incomplete restoration is durably
observable, forces session abandonment, and cannot satisfy the release gate.

## Correctness matrix

Each run uses a unique token and a bounded pcap/pcapng capture to prove:

- TCP over IPv4 and IPv6;
- UDP and QUIC;
- DNS A and AAAA through the selected resolver;
- LAN bypass;
- included and excluded route behavior;
- stop cleanup and restoration;
- sleep/wake and network-path recovery;
- provider and ProxyAgent crash behavior;
- generation/digest mismatch rejection and late-callback handling.

When IPv6 is disabled, neither an IPv6 route nor an IPv6 resolver may be
published. A successful mode transition requires matching generation, config
digest, provider readiness, and OS status.

## Release evidence

Store exactly three performance raw subjects under the evidence root:
`sample-ledger` (`performance-sample-ledger`), `shaping-intent`, and
`shaping-restoration` (both `performance-shaping-transaction`). The pre-nonce
observation manifest freezes their subject, kind, path, size, and digest. The
post-nonce materializer only reopens those bytes; it never remeasures. The v5
aggregate validator recomputes every summary and requires a source-pinned
signed collector receipt over the complete report/raw set. See
[Physical evidence v5](physical-evidence-v5.md). CI may run fast
deterministic unit tests, but physical Apple Silicon data-plane, weak-net,
resource, soak, and external collector-trust gates remain mandatory publication
gates.
