# Build 40059: DNS recovery and manual testing handoff

40059 was built from `46a3ad67e87eb522981bb6c047025ec5bfa4aeba`, signed,
notarized (`fc3d1de4-7881-4189-8231-de2720169812`) and installed. Its app tree
digest is `2cab554855d7a795ba100da2e45f65bdad9bd395a87abe96613aa3ab7c1621a1`.
TUN, combined mode, and System Proxy carried successful HTTPS requests. Pure
TUN later showed DNS and TCP timeouts; those failures remain preserved.

The default encrypted DNS pair required TLS 1.3 from both operators. Through
the selected existing SOCKS node, the pinned sing-box runtime successfully
queried the primary AliDNS resolver but the secondary `doh.pub` endpoint
returned `remote error: tls: handshake failure`. An independent TLS client
observed the same refusal. That secondary could not serve its fallback role.
The same runtime queried Cloudflare and AliDNS successfully while bound to
en0, without changing OS proxy/DNS settings or CFW. 40060 retains AliDNS as
the primary and replaces the failing secondary with Cloudflare; TLS 1.3,
certificate identity checks,
the selected outbound, and explicit user DNS choices are preserved.

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

Evidence is in `target/dns-recovery-20260912` and
`/Users/bill/cfw-release-history/network-start-40059-20260911`, including the
failed pure-TUN runs and the 01:09 incident timeline. 40060 installation and
manual runtime acceptance remain separate work.

The direct CLI regression requires the existing closed release runtime. The
supply-chain regression was corrected to include the fifth (profile-probe)
patch and the independently verified combined source digest. A stale cache
receipt in the already-retired 40052 checkout referenced a pre-build commit;
its actual checkout matched the signed 40052 manifest. The clean, inactive
checkout and all artifacts were archived without deletion at
`/Users/bill/cfw-release-history/retired-worktrees/40052`, retaining the original
receipt and recording the relocation separately. No cache admission rule was
weakened to make the current workspace pass.
