# Build 40064: owner-initiated stop and IPv6 DNS compatibility

Build 40064 completed signing, notarization, installation and a verified test
ZIP from `7fa42479443bd5c59b57bc83a24694af4f46ff7d`. Preserve its frozen source,
signed application and receipts under `target/release-worktrees/40064` and
`/Users/bill/cfw-release-history/liveness-install-40064-20260915/`.

Installed repeated local startup, automatic Wi-Fi startup, manual stop and a
twelve-second Off observation passed. With CFW TUN disabled, explicit CFM proxy
HTTPS, download and three UDP STUN transactions passed. Initial pure-TUN HTTPS
failed. A direct upstream comparison accepted domain/IPv4 HTTPS, while the same
target over IPv6 ended with TLS EOF. A temporary profile IPv4 DNS policy then
passed pure-TUN HTTPS, download and all three UDP transactions. System DNS
returned only IPv4 addresses, while the CFM IPv6 default route remained present.
The temporary profile policy was restored through the application transaction;
all four credential references remained available.

The first bounded TUN check stopped the CFM service using the public system VPN
stop operation. At 04:35:11 the Provider's stopped attestation was rejected as
`stale_operation` while the Authority was still Active, followed by quarantine.
The reducer accepted stopped owners only from Starting or Stopping, omitting
the normal system-originated disconnect of an Active provider. The old-source
regression reproduces this rejection. The correction accepts the exact bound
owner's proof into Stopping; it retains the lease until the Host independently
proves the complete Off barrier. Wrong-peer rejection, replay, no premature new
lease and a subsequent start are covered. Linked-native regression passed 676
tests before successor allocation.

40065 also exposes an IPv6 DNS preference through the existing runtime settings
transaction. Its default preserves existing behavior and canonical settings
bytes. Disabling IPv6 DNS suppresses AAAA answers without removing IPv6 packet
capture. Rust and UI regressions passed before successor allocation. The actual
40065 installed behavior still needs verification.

System Proxy permission in 40064 required an unanswered macOS authorization
dialog. The request was cancelled without starting the core; no System Proxy
acceptance is claimed. The CLI's separate authorization did not prove that the
CFM process held that non-shared right. This is separate from the product-byte
changes requiring 40065. No receipt is relabelled and no public GA release is
claimed. CFW, recovery journals, user profiles and credentials remain preserved.
