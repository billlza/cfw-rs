# Build 40052 network startup correction

40052 was signed, notarized, installed and tested for disconnected proxy controls.
Its frozen application, source and receipts remain unchanged. System Proxy and
TUN activation did not complete acceptance; no public GA release completed.

On September 11, macOS rejected the Packet Tunnel extension because its
`NEMachServiceName` did not begin with an entitled App Group. The package and
the verifiers had shared the same incorrect expected name. The successor uses
the existing App Group plus `.packet-tunnel`; a regression checks the actual
relationship between the shipped plist and entitlements, and rejects the old
team-only prefix.

Engine state events also advanced the renderer's snapshot request counter while
a switch request was pending. The renderer then discarded the switch's eventual
failure. Switch completion now refreshes newer state without dropping operation
errors, and the latest operation error takes precedence over an older failure.

The native bridge retains separate bounded error codes for extension validation,
System Proxy configuration, runtime startup, preferences, recovery journal and
authority confirmation. Arbitrary native messages still cannot expose profile
credentials through the public error response. The additive codes retain the
v9 envelope and existing unknown-code rejection; durable schemas are unchanged.

40053 is the successor candidate for installation and continued runtime diagnosis.
Successful disconnected probes, configuration parsing and isolated native runtime
start/stop tests do not establish successful System Proxy or TUN activation.
