# Build 40054 Tunnel credential transport correction

40054 was frozen at source 92f140c1155d3cf6071ee127f95fc3b3b403ecc0,
signed, notarized (3f624137-d6ea-43b9-941f-2de247f03983), and installed.
Its System Proxy started, served two HTTPS requests returning 204, and restored
the preceding proxy settings when stopped. Those outbound requests traversed
the still-running CFW TUN, so they do not establish standalone CFM acceptance.

macOS activated the 40054 Packet Tunnel extension. The following real-node start
failed with SecretBoundsExceeded before the Authority mutated its Off state.
The NativeBridge still encoded credentials as the old binary plist payload,
while the Authority decoded only CFWASV01. Empty-credential fake starts had not
exercised this disagreement. The failed request was canceled and native Off was
proved; the existing CFW proxy settings remained unchanged.

40055 replaces that product encoding with the shared Authority codec. It binds
secrets to descriptor order, handles a shared reference once, and includes the
bounded framing overhead in the transport buffer limit. Missing, extra,
conflicting-kind and oversized secrets still fail. No code-signing, ownership,
credential-audience, journal or macOS authorization check is removed.

The regression using non-empty credentials and the production decoder failed
on the old implementation and passed on the correction. The complete Swift
suite passed 626 tests. Installed System Proxy/TUN/combined-mode acceptance is
still required for the successor. All 40054 frozen bytes and receipts remain
unchanged; this retirement follows a product change, not an evidence retry.
