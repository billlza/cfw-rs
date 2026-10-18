# Build 40071 retirement

Build 40071 consumed its candidate identity and was signed, notarized, stapled
and installed. Its product source is `f4ab9801b00a8ba0e6b2dcc0be3981d289025e1e`;
the installed and retained signed application tree is
`78dce25dc8db98498f5637c47ad37e297451a81fe2f53f841c225d5486fd4754`.

During local acceptance, 18 of 508 HTTPS availability probes failed. Paired
socket measurements observed working SOCKS negotiations lasting 6.5 and 13
seconds while 40071 cancelled its setup after five seconds. A real-socket
regression reproduces premature cancellation during protocol negotiation and
before a configured secondary DNS server can be queried.

Using the existing protocol-handshake budget instead of the TCP socket-connect
budget changes libbox application bytes. Build 40071 is therefore retired as
`retired_product_change_after_install_before_ga_runtime_acceptance`; 40072 is
the unconsumed successor. This is a product change, not a retry of its completed
notarization or installation. Its artifacts, failed samples, source commit and
append-only journals must be retained unchanged. No public release occurred.
