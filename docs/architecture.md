# macOS 15+ architecture

## Product boundary

The product supports Apple Silicon and macOS 15 or newer. It has two mutually
exclusive network modes:

- System Proxy: a signed, non-root user ProxyAgent owns one libbox mixed
  inbound and applies SystemConfiguration preferences transactionally.
- Tunnel: a Packet Tunnel System Extension owns one libbox instance and uses
  public Network Extension packet-flow methods.

Every Proxy-to-Tunnel or Tunnel-to-Proxy change passes through Off. The old root
helper and external Clash-compatible core are retired and never act as a
fallback.

## Dependency direction

```text
Tauri commands/UI
  -> cfw-application
     -> cfw-engine-api
     -> cfw-singbox-config
     -> cfw-apple-network
        -> narrow signed Swift Host Bridge
           -> NETunnelProviderManager / authenticated ProxyAgent XPC
```

`cfw-singbox-config` has no Apple dependency. `cfw-engine-api` owns stable
product and wire types. `cfw-application` owns serialized use cases and state
transitions. `cfw-apple-network` adapts native failures into domain errors.
Swift owns Apple framework integration but not a second product state machine.

## Engine state

The state set is:

```text
Off
ProxyStarting -> ProxyActive -> ProxyStopping -> Off
TunnelInstalling -> AwaitingApproval -> TunnelStarting
  -> TunnelActive -> TunnelStopping -> Off
Failed
```

One bounded coordinator actor processes commands. Caller cancellation does not
cancel a transition already accepted by the actor. Backend errors are typed and
observable; a failed start becomes Failed and never tries another engine.

The actual Agent or System Extension process must hold one globally arbitrated
engine lease for the full libbox lifetime. A user App Group file cannot provide
that arbitration for a system extension: the system extension runs as root and
resolves the same App Group identifier into a different container. The current
prototype therefore blocks Tunnel startup until a signed, identity-checked XPC
state transport and global lease service replace that false-sharing design.
Intent and observed-state journals remain single-writer, versioned, and
protected by installation ID, configuration epoch, generation, length, and
SHA-256 digest.

## Configuration and credentials

One `ValidatedSingBoxProfile` plus `EngineSettings` deterministically produces
separate Proxy and Tunnel projections. Business configuration is not copied
into two independent models.

The validator accepts a deliberately closed local JSON schema: one to 128
uniquely tagged `direct`, `block`, Shadowsocks, VMess, VLESS/Reality, Trojan,
Hysteria2, AnyTLS, or TUIC v5 outbounds and, optionally, `route.final` naming a
declared tag. Protocol fields, TLS, transports, endpoint syntax, limits, and
credential kind are typed and unknown fields fail closed. TUIC owns separate
UUID and password slots; Hysteria2/TUIC QUIC TLS rejects uTLS and Reality while
AnyTLS follows the standard TLS path. The projection layer owns a TLS 1.2
minimum for every enabled remote TLS transport and authenticated DoH server;
normal negotiation prefers TLS 1.3 and QUIC still requires TLS 1.3. Projection
also emits TUIC with 0-RTT disabled; neither control is profile input.
User-managed DNS/services,
subscriptions and remote resources, scripts, executable paths, and raw secret
values remain forbidden. This is not full sing-box compatibility.

The subscription source boundary accepts only a restricted upstream sing-box
`outbounds` document, a Clash/Mihomo `proxies` list, Shadowsocks SIP008 JSON,
or a bounded URI bundle. VMess accepts traditional base64 JSON and the
URL-shaped AEAD form; the latter cannot carry legacy `alterId` state.
Hysteria2 multi-port sources normalize into a bounded non-overlapping port set
and an optional fixed-second hop interval before projection to sing-box 1.13.
Shadowsocks 2022 sources normalize the method first and validate each
standard-base64 key in a single- or multi-user PSK chain before allocating any
credential reference; SIP002 URI input additionally rejects Base64 userinfo.
It extracts source secrets before constructing the closed profile and rejects
root-level sing-box DNS, inbounds, routes, selectors, scripts, and unknown
fields. Source refresh reuses references in outbound order when possible; an
exact immutable-material conflict is the sole authorization to rotate IDs.
Repository-bound vault garbage collection runs before and after refresh so an
old audience cannot accumulate silently or be deleted while still live.
The repository revalidates the exact stored profile under the same lock before
any refresh can provision a new audience. A missing vault is a clean no-op only
when the repository has no live credential references.

Profile files store only canonical `credential_ref` objects. Deterministic
projection removes those references from libbox JSON, leaves an empty string
at each exact secret target, and emits a separate closed credential-slot list.
The configuration identity covers the secret-free template and slot
references, never secret-derived bytes. References are immutable across all
profile audiences: provisioning an existing UUID is allowed only for the same
kind and byte-identical secret;
rotation creates a new UUID and updates the profile. The UI queries presence
and submits only the missing subset, while the native transaction also receives
the profile's full reference set and rejects every missing, extra, duplicate,
kind-mismatched, or conflicting entry atomically. Owned secret buffers are
zeroized at the renderer-command and native bridge boundaries. Installed-
signature and entitlement proof remain release gates; no empty placeholder may
reach a running libbox instance.

Deleting a profile or rotating a UUID does not leave permanent Keychain
orphans. Garbage collection is an explicit two-phase operation. Its preview is
bound to a canonical digest of every selected and staged profile, a sorted live
reference set, and the vault revision. Commit requires the replacement engine
to be exactly Off, holds both the application maintenance lease and the
repository's cross-process lock, re-reads the same snapshot, and performs one
Keychain compare-and-swap. Shared references stay live; expiry, concurrent
provisioning, repository mutation, corruption, or confirmation drift deletes
nothing.

The user App Group stores only bounded, versioned, non-sensitive ProxyAgent
configuration and journal data. It is not a host-to-system-extension transport.
The Packet Tunnel system extension must receive configuration through its
authenticated global XPC boundary and keep provider-owned non-secret replay
state in a root/global-context store. User credentials remain in the dedicated
Host/ProxyAgent Keychain access group. A Tunnel secret is read by the
authenticated Host, transferred through XPC only in memory, and injected by
the global authority immediately before libbox start. The System Extension
does not claim direct access to the user's Data Protection Keychain, and secret
bytes never enter App Group or journal storage.

Engine DNS has two non-interchangeable roles in both modes. Bounded numeric UDP
bootstrap transports dial directly and are referenced only by domain-named
proxy server outbounds. All ordinary engine queries use certificate-verified
DoH transports whose `detour` is the selected profile outbound, and route-level
destination resolution uses the same authenticated role. Tunnel additionally
hijacks packet-flow port 53 into this path. No resolution cycle exists: each
DoH endpoint is numeric, while a domain-named selected outbound explicitly
resolves only its own endpoint through the bootstrap pair. The pinned source
patch represents both resolver roles as strict primary/fallback pairs and
permits one bounded fallback after a rejected response or transport error. It
never falls back after cancellation and never attempts either server more than
once. Building that exact patch into libbox and proving both paths by physical
packet capture remain release gates; unpatched sing-box 1.13 does not provide
these semantics.

Engine generation lineage is a canonical, bounded document in the host app's
own Data Protection Keychain access group. Its revision label is the SHA-256 of
the document and Keychain updates compare against the prior label, preserving
compare-and-swap semantics across processes. The Application Support copy is
only a repairable cache and serialization aid: deletion, rollback, or tampering
cannot select an older installation identity, epoch, or generation.

Native requests accept only fixed relative slots. Absolute paths, executable
paths, scripts, arbitrary environment variables, and user-selected commands
are not part of the contract.

## Native security boundary

The ProxyAgent validates the connecting user and exact signed code identity,
including Team ID and allowed bundle identifier, before exporting a typed and
bounded XPC interface. The System Extension is sandboxed and uses exact App
Group and Network Extension entitlements, but treats its App Group container as
root-owned provider-local state. Its global XPC listener must authenticate the
Team ID, bundle identity, audit token, active console user, and multi-user lease
ownership before accepting configuration or mode requests.

The Packet Tunnel adapter uses bounded nonblocking socketpairs and public
`NEPacketTunnelFlow` reads/writes. It validates packet/protocol count,
packet lengths, batches, cancellation, close, and backpressure. Accessing
private packet-flow file descriptors through KVC is forbidden.

## Activation truth

System Proxy is active only after the mixed listener is ready and the intended
SystemConfiguration values have been applied. Stop restores only fields that
still equal this product's applied values, so user or administrator changes are
not overwritten.

Tunnel is active only when `NEVPNStatus.connected`, the provider reports ready,
and its generation and configuration digest match current intent. Interface
existence or a saved preference alone is never treated as success.
