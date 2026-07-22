# macOS platform foundation

The platform boundary targets arm64 macOS 15 and newer.

`cfw-platform` retains only ordinary user-context adapters such as login items,
diagnostics, file dialogs, and transitional cleanup. It does not own a root
data plane. Privileged network behavior belongs behind the signed native
Network Extension/ProxyAgent boundary in `native/macos` and
`cfw-apple-network`.

## Supported boundaries

- Login items use the public ServiceManagement user-login APIs.
- System Proxy changes use SystemConfiguration preferences transactionally.
- Tunnel installation and status use SystemExtensions and NetworkExtension.
- Shared non-sensitive user-mode state uses a versioned App Group contract.
- The root/global Packet Tunnel system extension uses authenticated XPC and its
  own provider-local state; it never treats the user App Group as shared files.
- User-mode credentials use Data Protection Keychain groups. System-extension
  secrets must be owned in the file-based System Keychain after authenticated
  IPC transfer.
- Anti-replay generation lineage uses the host-only Data Protection Keychain
  group; ProxyAgent cannot read or replace it, and the Packet Tunnel has no
  Data Protection Keychain entitlement.
- Native errors are mapped into explicit domain errors and never converted to
  success, empty state, or an alternate engine.

## Retired boundary

The old helper label, control session, root core, routes, and DNS settings are
handled only by the one-way migration cleanup. Cleanup can stop, remove, verify,
and unregister; it can never start a core. Any incomplete cleanup becomes an
explicit manual-cleanup-required state and blocks all new network modes.

Startup is not a cleanup trigger. It either re-verifies a previously completed
retirement without mutation or leaves the legacy network in
`awaiting_confirmation`. New profiles use `sing-box-profiles-v1`; historical
Clash profiles remain under `profiles`, so pre-cutover staging cannot be
deleted by the legacy cleanup transaction. The destructive command requires a
positive user confirmation, an exclusive engine-maintenance lease, a selected
valid replacement profile, an Off replacement engine, and signed-native
credential/System Extension preflight readiness before the app performs the false-first retirement transaction. The tombstone descriptor itself performs no cleanup or network mutation.

Legacy proxy and DNS values are not blindly restored from an old snapshot.
Proxy cleanup verifies that the relevant SystemConfiguration services are no
longer enabled. DNS cleanup requires an explicit review action because the old
snapshot does not prove that the current value is still owned by this product.
An ambiguous, changed, or still-enabled value remains visible as a blocking
manual action; cleanup does not overwrite a later user or administrator change.
