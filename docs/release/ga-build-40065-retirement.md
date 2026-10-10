# Build 40065: consume the completed native stop

Build 40065 was signed, notarized and installed from
`303c807c45df46b76571eb8cba687266a7c15e9d`. Its frozen source and original
receipts remain under `target/release-worktrees/40065` and
`/Users/bill/cfw-release-history/tun-compat-install-40065-20260915/`.

Installed local proxy, pure TUN and TUN with System Proxy passed real HTTPS,
downloads and UDP. A Foundation URLSession request selected the actual CFM
system proxy on port 7891 and returned HTTPS 204. Normal Stop reached native
Off and restored the previous CFW proxy. Offline latency testing passed both
nodes while the native engine stayed Off. IPv6 DNS suppression returned A
answers and AAAA NODATA while retaining the CFM IPv6 capture route. A persistent
UDP session received all twenty replies, with median RTT 116.739 ms. These are
observations for the tested endpoint, not an overall performance ranking.

The system-originated VPN stop now completed at the native layer without an
Authority restart. However, the Rust coordinator treated the authenticated
global Off observation as if the old owner still required teardown. It retained
its local lease. The next Retry therefore sent StopTunnel for an owner whose
descriptor no longer existed and received IdentityRejected. Native Off still
passed independently. The installed failure and a matching old-source regression
are preserved; a fake backend that always accepted repeated stops had masked
this application/native contract conflict.

40066 releases only the local bookkeeping lease after a successful authoritative
native Off observation. The unexpected-disconnect error remains visible until
the user acknowledges or retries it. Failed queries, ambiguous ownership and
identity drift continue to retain the exact cleanup lease. Native authentication,
owner-stopped attestation and independent OS Off validation are unchanged.
The regression covers reconnection in all four modes and ordinary cleanup of
the new generation. The changed Host bytes require a new candidate identity.

The operator installer also admits an OS-managed idle extension only after
native Off, VPN Disconnected, exact predecessor executable hash, signed bundle
identity and root-owned process checks. macOS successfully replaced the idle
40064 extension with 40065 without a forced process termination. This operator
correction does not weaken the frozen product's runtime ownership checks.

Standalone System Proxy authorization and the successor's installed reconnect
acceptance remain outstanding. No public GA publication is claimed.
