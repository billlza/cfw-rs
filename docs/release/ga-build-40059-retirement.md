# Build 40059: DNS recovery and manual testing handoff

40059 was built from `46a3ad67e87eb522981bb6c047025ec5bfa4aeba`, signed,
notarized (`fc3d1de4-7881-4189-8231-de2720169812`) and installed. Its app tree
digest is `2cab554855d7a795ba100da2e45f65bdad9bd395a87abe96613aa3ab7c1621a1`.
TUN, combined mode, and System Proxy carried successful HTTPS requests. Pure
TUN later showed DNS and TCP timeouts; those failures remain preserved.

The first diagnostic forced a TLS 1.3 minimum and observed a handshake failure
from `doh.pub` through the selected SOCKS node. That diagnostic was stricter
than the product: both 40059 and 40060 use a TLS 1.2 minimum and negotiate
TLS 1.3 when supported. A subsequent test using the actual Rust projection
and pinned runtime successfully queried both old resolvers, including fallback
after deliberately rejecting the primary TLS identity. The forced-TLS result
therefore does not establish the cause of the earlier pure-TUN timeout.

40060 retains primary AliDNS and replaces the secondary with Cloudflare, which
also passed the stricter TLS 1.3 diagnostic. The actual final projection passed
primary, secondary, automatic, and rejected-primary fallback queries while
bound to en0, without changing OS proxy/DNS settings or CFW. This is a tested
resolver compatibility change; the product TLS minimum, certificate identity
checks, selected outbound, and explicit user DNS choices are unchanged.

74 configuration tests passed. A local protocol regression uses real TLS and
DNS messages to show that a rejected primary identity can use the separately
authenticated fallback, both rejected identities fail without an answer, and
successful fallback works after restart. The existing transport, fake-IP,
WireGuard, multihop, and TLS checks also passed. This does not by itself close
installed TUN or long-running network acceptance.

At 01:08:48 on September 12, an old diagnostic's delayed AX cleanup disabled
TUN after the user had begun using both switches. That was interference by the
test operator. It must not be described as proof of spontaneous engine failure.
The subsequent System Proxy endpoint conflicts recovered through the existing
bounded endpoint selection; the Authority journal later reached Ready and Off.
Seven old diagnostic entrypoints were permanently retired, with their executed
source and failures preserved outside the repository.

Live validation must not schedule an unowned `finally` action against the GUI.
After a timeout, terminal diagnostic result, process/mode drift, or manual test
handoff, no delayed network action may be issued. Isolated probes may release
their own sockets and processes; the person using CFM owns its switches during
manual testing. This is a test-operation rule, not a new product startup gate.

Evidence is in `target/dns-recovery-20260912`, including
`projected-old-dns-actual-policy-results.json` for the corrected old-policy
comparison, and
`/Users/bill/cfw-release-history/network-start-40059-20260911`, including the
failed pure-TUN runs and the 01:09 incident timeline. 40060 was signed,
notarized, and installed; its two configured nodes passed latency checks with
the engine Off. Installed pure-TUN restart and long-running network acceptance
remain open. The installation and package receipts are in
`/Users/bill/cfw-release-history/network-start-40060-20260912`.

The direct CLI regression requires the existing closed release runtime. The
supply-chain regression was corrected to include the fifth (profile-probe)
patch and the independently verified combined source digest. A stale cache
receipt in the already-retired 40052 checkout referenced a pre-build commit;
its actual checkout matched the signed 40052 manifest. The clean, inactive
checkout and all artifacts were archived without deletion at
`/Users/bill/cfw-release-history/retired-worktrees/40052`, retaining the original
receipt and recording the relocation separately. No cache admission rule was
weakened to make the current workspace pass.
