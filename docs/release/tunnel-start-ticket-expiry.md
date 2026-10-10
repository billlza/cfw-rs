# Tunnel start ticket expiry

The installed 0.4.0 build 40068 failed before starting libbox on 2026-09-15.
macOS accepted the start command at 23:00:31.399 and delivered it to the new
Provider at 23:00:41.363. The Provider received the complete 32-byte ticket and
passed Authority peer authentication. Redemption failed at 23:00:41.387 with
`ticket_expired`. The ten-second preparation lifetime had elapsed during the
OS extension launch. This observation does not establish whether a later warm
start would have succeeded.

Two error boundaries hid the cause: Provider redemption mapped expired tickets
to invalid tickets, and the Host treated a disconnected Provider as Off while
waiting for readiness, eventually returning a generic timeout.

The correction preserves the ten-second, one-use ticket contract. A bounded
NSError now carries the exact expired-ticket cause and non-secret start
lineage through NetworkExtension's public last-disconnect-error API. The Host
matches it only to a pending start and ignores stale errors from other
generations. Readiness observation allows twenty seconds for the OS to report
the terminal outcome. Exact cleanup and independent global Off remain required
before one automatic retry can allocate a fresh generation. A second expiry,
invalid/replayed ticket, cleanup failure, or newer user intent ends that retry
path explicitly.

The screenshot's IPv4-only DNS setting is separate. The installed preferences
had `ipv6_dns_enabled: false`. IPv6 packet capture and routes remain controlled
independently by `enable_ipv6`. Neither local proxy success nor these source
checks constitute physical IPv6 or standalone TUN acceptance.

Validation records and failed attempts are retained outside the repository.
Regression coverage includes the old misclassification, NSError secure coding,
stale lineage rejection, asynchronous native failure and exact cleanup, fresh
generation retry, retry exhaustion, failed Off proof, replay rejection and
queued user cancellation. A signed replacement still requires installation and
physical TUN validation before this defect can be called resolved in the app.
