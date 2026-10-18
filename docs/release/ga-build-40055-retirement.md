# Build 40055 Tunnel authorization and provider-session correction

40055 was frozen at eb87b641631a01d8495374ee4e047ed37ffa4c85, signed,
notarized (a0aea9c1-e9fd-45ef-b4a8-fc88f7ffd2ac), and installed. Its credential
transport correction passed the real Authority boundary, and macOS activated
the 40055 Packet Tunnel extension. It was not accepted as a working TUN build.

The first VPN-configuration consent remained open after the five-second
preference callback deadline. Compensation removed the newly approved manager,
so another attempt repeated the same consent. The short-lived Authority ticket
had also been issued before that human interaction. A diagnostic accepted the
same CFM permission promptly; the Provider then actually launched, but reported
that its start ticket was missing or invalid. The Host called the ordinary
NEVPNConnection.startVPNTunnel API instead of NETunnelProviderSession.startTunnel,
which Apple's SDK documents as forwarding custom options as-is.

40056 separates first-time consent from runtime start. It proves global Off,
saves only a disabled descriptor-only manager with a durable compensation
receipt, and waits under the bounded authorization budget. It neither resolves
credentials nor issues a ticket during that wait. Once consent is complete,
the normal short-lived ticket, enabled preference transaction and provider
start follow. A removed consent configuration fails explicitly. Runtime and
cleanup deadlines, credential bounds, ticket validation and ownership checks
remain intact. The provider-specific API carries the same single opaque ticket.

A real NETunnelProviderSession subclass regression failed using the old API
and passed using the provider API. Coordinator regressions cover delayed,
rejected and unanswered consent; native tests cover no credential access during
consent, active-owner rejection and preserved denial errors. The Swift suite
passed 630 tests. Installed 40056 networking and delayed-consent validation
remain required. All 40055 application bytes, receipts and failed observations
are retained unchanged. CFW processes and the original proxy settings remained
in place throughout these attempts.
