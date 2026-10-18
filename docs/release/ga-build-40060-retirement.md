# Build 40060: superseded by the UDP/DNS reliability update

Build 40060 was signed, notarized and installed from
`ec79ca5f8c28ee0e56d9e5ff5fac5d1a0e0fab34`. Its source, signed application,
Apple submission and original runtime evidence remain immutable. The user has
requested installation of the subsequent UDP/DNS fixes.

Build 40061 changes actual product inputs: it bounds SOCKS setup cancellation
and timeouts, handles wildcard UDP relay addresses without losing the configured
detour, and updates the sing dependency by one upstream bug-fix commit to repair
UDP association cleanup concurrency. The six DNS transports pass repeated
uncached exchanges directly and through SOCKS with the race detector enabled.
See [the detailed verification record](../udp-dns-reliability-0.4.0.md).

This is a successor for changed product bytes. Test, documentation, packaging or
evidence retries are not reasons to consume another application build number.
The signed 40060 lineage must not be relabelled or rebuilt as 40061.

The local replacement must preserve stored profiles, credential references,
user settings and journals. Network configuration may not be changed as a
side effect of installation. Installed runtime and sustained TUN/video acceptance
remain separate from component tests and notarization.

The original 40060 handoff and package receipts are retained under
`/Users/bill/cfw-release-history/network-start-40060-20260912/`; the 40061
construction and installation receipts belong under
`/Users/bill/cfw-release-history/install-udp-dns-40061-20260914/`.
