# Build 40061: superseded by everyday proxy and policy support

Build 40061 was signed, notarized and installed from
`7b87b53cc102fc34e2fd259078344fb4c77380c3`. Its application, source, Apple
submission and installation receipts remain immutable under
`/Users/bill/cfw-release-history/install-udp-dns-40061-20260914/`.

The user approved the client parity plan and its installation. Build 40062
changes actual product inputs: independent local proxy, online profile
transactions, providers and balancing, DNS policy, editable runtime settings,
larger bounded subscriptions, HTTP/TLS pins and explicit background controls.
See [implementation and evidence](../client-parity-implementation.md).

40062 is a new application lineage because the installed 40061 bytes have
already consumed their build number. Source tests, evidence collection and
packaging retries do not independently require another number. No predecessor
receipt is deleted or rebound to the new source.

Installation preserves profiles, Keychain credentials, settings, recovery
journals and the working network. The old app is replaced only after the new
signed package is verified and current ownership permits a controlled swap.
Sustained networking remains distinct from source checks and notarization.
