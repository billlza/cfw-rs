# Build 40068 Tunnel startup successor

Build 40068 was signed, notarized, stapled and installed. Its local proxy and
offline node tests succeeded, but a user-triggered TUN start failed before
libbox initialization. The OS delivered the start to the Provider after the
single-use ticket had expired. Provider authentication succeeded; Authority
redemption returned `ticket_expired`. See
[`tunnel-start-ticket-expiry.md`](tunnel-start-ticket-expiry.md).

The correction changes the product's native error transport, start observation
and bounded fresh-generation retry. The allocation ledger therefore records
40068 as `retired_product_change_after_install_before_ga_runtime_acceptance`
and allocates 40069 as the active successor. This does not claim that runtime
acceptance or publication of 40069 has completed.

The installed and frozen 40068 application trees were independently measured
and match SHA-256 tree v2
`422197244ef7f336b529f03d51d012a52b25d555178014c70dd519c8ee3e216c`.
Both trees, failed-start logs, signing and notarization records, configuration
and existing network state remain preserved. This allocation does not alter
running CFW/CFM processes or operating-system networking.

The ten-second ticket lifetime, authentication, replay prevention, cleanup
barrier and publication requirements remain enforced. Source checks that fail
before construction can be retried with this same unconsumed build number.
