# Build 40058 real TUN interface binding correction

40058 was frozen at `d31f6339346cf8cbdb1c61ad0af74c588569d6ee`, signed,
notarized (`f0ac5380-fcfd-4854-8369-c9a67ebba5bf`) and installed. Its application
tree digest is `508f6f02c8b52c8a39b01fd7702d5eda6eaf77352b0fa9fda476ebb5608a088e`.
The Provider's real root audit session 100018 was accepted, proving the identity
policy correction. Combined TUN/System Proxy startup also succeeded; two HTTPS
requests through the CFM mixed listener returned 204, with the Provider's remote
node connections observed on en0. Pure TUN TCP requests still timed out.

The raw Packet Flow adapter replaced the kernel interface name with the label
`cfw-packet-flow`. The system TCP stack uses that name to bind its kernel TCP
forwarder. An isolated test against the installed, addressed TUN reproduced the
old failure: binding through the adapter's name returned `no such network
interface` while the real interface was utun11. The corrected adapter resolves
one active point-to-point utun matching every configured tunnel address via
public interface enumeration. The same real-interface test then passed and
verified the socket's bound interface index. Missing, partial, physical, down
and ambiguous matches fail explicitly; descriptor ownership is cleaned up on a
resolution failure. No private NetworkExtension descriptor or route mutation
is introduced by this resolver.

Installed route observations also showed the virtual DNS/TCP peer could resolve
through CFW's more-specific benchmark-range route, and macOS logged invalid
loopback exclusions. 40059 includes its own IPv4/IPv6 virtual subnets explicitly
and omits loopback exclusions that macOS rejects. The separate temporary peer
route experiment did not itself repair TCP and was fully reverted; it is not
claimed as proof of the interface-binding fix.

634 native tests and the raw-adapter race tests passed. Real 40059 forwarding,
normal stop and restart remain required. A later 40058 stop entered cleanup
quarantine; restarting the existing Authority through launchd and allowing the
normal recovery barrier restored a verified Off state without deleting journals.
The isolated UI harness also encountered transient accessibility failures;
those are retained separately from product failures.

The original notarization upload timed out and a process-proxy retry was
ineffective. A same-archive retry through a bounded transparent HTTPS relay
uploaded in about 21 seconds and was Accepted. Original proxy/DNS settings and
CFW processes were verified restored, and the relay was closed. All original
uploads, byte identities, runtime failures and recovery evidence are retained.
