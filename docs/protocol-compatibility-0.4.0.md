# 0.4.0 protocol compatibility and optional Xray assessment

Assessment date: 2026-09-14. The application model, credential transport,
projection and running core must all support a combination before it is accepted.
A protocol name alone is not a compatibility guarantee.

| Combination | Current implementation | Evidence or boundary |
| --- | --- | --- |
| SOCKS5 TCP and UDP | Supported, including authenticated endpoints | Actual TCP/UDP, cancellation, relay address and destination isolation regressions |
| HTTP / HTTPS CONNECT | Supported, anonymous or Basic authentication | Actual CONNECT, correct/incorrect credentials, trusted/untrusted TLS and explicit UDP rejection |
| TLS certificate / SPKI SHA256 pin | Supported as distinct pin kinds | Correct pin passes; wrong pin, name, time or empty certificate chain fails |
| VMess, VLESS, Trojan and Shadowsocks | Supported within the existing closed import model | Unsupported transport/plugin fields remain explicit errors |
| Hysteria2, TUIC and single-peer WireGuard | Existing support retained | Local protocol interoperability and wrong-key rejection; not a claim that every subscription variant is supported |
| SOCKS5 / Shadowsocks UDP-over-TCP | Not exposed | Requires matching server support; an ordinary SOCKS5 server cannot acquire it from a client option |
| Shadowsocks external plugins, arbitrary smux, SSH | Not exposed | No complete application/credential/runtime contract in this release |
| XHTTP and Xray VLESS Encryption | Not implemented | Optional backend assessment below; never silently translated into a different transport |

The new HTTP username/password slots remain in the native credential path.
Subscription HTTP requests use the running local proxy when available, preserving
public-address validation and TLS verification. Proxy failure does not trigger
an undocumented direct retry.

Certificate pins authenticate the configured leaf certificate or public key.
They can authorize a self-signed endpoint, but they still require the configured
server name, certificate validity interval and server-auth usage. A Clash
`fingerprint` is converted to a certificate hash, not a public-key hash.
The importer continues rejecting `skip-cert-verify: true`.

## Optional Xray

Xray has its own [XHTTP transport](https://xtls.github.io/en/config/transports/splithttp.html)
and [VLESS Encryption settings](https://xtls.github.io/en/config/outbounds/vless.html).
They differ from the [sing-box V2Ray transport model](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/).
Ordinary TLS hybrid key exchange does not implement VLESS Encryption.
The project also provides a [libXray wrapper](https://github.com/XTLS/libXray),
so an embedded integration is plausible; that is a feasibility finding, not
evidence that it is integrated into CFM or that it improves macOS performance.

No supplied node in the current work has established a requirement for XHTTP or
VLESS Encryption. The accepted plan makes adding another core conditional on
that need. Therefore 0.4.0 retains one sing-box runtime and does not add an idle
second backend merely to increase the protocol count.

If a required node needs Xray, the integration should use the existing engine
owner, configuration identity and native credential path. It requires a pinned
embedded artifact, closed model for the exact transport, TCP/UDP and DNS routing
semantics, bounded start/stop/cancellation, crash cleanup, telemetry and equivalent
installed acceptance. A separate unmanaged process or generic command launcher
would create another ownership path and is unsuitable. Running two independent
TUN owners is also unsuitable. The minimum proof is a configured local server
and a real required remote endpoint, including authentication failure and
recovery; successful config parsing is insufficient.

## Provider compatibility

HTTP resources over HTTPS and inline providers, app-owned intervals, group
membership, health checks, YAML/text domain/IP/classical rule sets and atomic
updates are implemented. File/MRS resources, arbitrary per-provider headers,
named download-route overrides and unrestricted field overrides remain outside
the closed import model. These are compatibility limits, not release test skips.

## Acceptance evidence

`target/client-parity-completion-20260914/parity-final-protocols-v1.log` records
the real local protocol lane with the Rust projector and race detector.
`http-pinning-real-v1.log` isolates HTTP certificate/SPKI positive and negative
paths. `tls-pin-red-v1.log` reproduces the old SPKI name/time defect;
`tls-pin-green-v2.log` covers its correction. Installed network quality, video,
power use and same-host competitor comparisons require separate observations.
