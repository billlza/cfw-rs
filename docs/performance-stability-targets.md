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
| Packet adapter throughput | at least 90% of same-machine libbox baseline |
| Packet adapter added latency | no more than 10% |
| Active idle CPU | below 1% |
| Active RSS | no more than 120 MiB |
| 100 mode switches | RSS growth no more than 5 MiB; FD growth no more than 2 |
| Soak | 3 operator-observed hours per pinned OS, no reported crash (internal limited release) |

Report sample count, warm-up, machine model, OS build, power mode, payload,
protocol, packet size, concurrency, raw observations, p50/p95/p99, and the exact
build/source identities. A gate script must fail when a probe is unavailable or
does not meet its threshold.

The 3-hour threshold is scoped to the current small internal distribution. A
future public GA must raise this profile after a separate review; 24 hours per
OS remains the recommended public-release target rather than an Apple-mandated
duration.

For v0.4.0 the soak record is an operator-controlled start/end interval plus an
ordered crash-event list. It is not a remote liveness attestation or a
monotonic-clock heartbeat trace. That lower assurance is accepted only for the
named small internal cohort; a future public release must add stronger
continuity evidence as part of its separate profile review.

## Weak-network matrix

- 100 ms latency, 1% packet loss, 10 Mbps;
- 300 ms latency, 5% packet loss, 1 Mbps;
- complete 30-second outage.

After path restoration, recovery p95 must be no more than 10 seconds. There
must be no busy loop, unbounded queue, stale Active state, duplicate libbox
instance, leaked socket/FD, or silent packet drop. Queue admission and drop
metrics must be bounded and observable.

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

Store raw measurements as strict artifact descriptors under the evidence root.
The v5 aggregate validator reopens and hashes the bytes, recomputes every summary, and
requires a source-pinned signed collector receipt over the complete report/raw
set. See [Physical evidence v5](physical-evidence-v5.md). CI may run fast
deterministic unit tests, but physical Apple Silicon data-plane, weak-net,
resource, soak, and external collector-trust gates remain mandatory publication
gates.
