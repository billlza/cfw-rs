# Build 40069 IPv6 DNS successor

Build 40069 was signed, notarized, stapled and installed. The user confirmed
that ordinary networking works well. The requested direct IPv6 DNS switch also
corrects a real preference-precedence bug: an imported `dns.ipv6: false`
previously defeated an explicit manual enable. The new projection respects
the manual choice and the UI displays the effective policy.

These shipped application changes require successor 40070. The allocation
ledger records 40069 as `retired_product_change_after_install_before_ga_runtime_acceptance`.
This does not invalidate its observed working connectivity or claim that
40070 has passed independent runtime acceptance or public release checks.

The installed and frozen 40069 application trees were independently measured
and match SHA-256 tree v2 `edca78995aacfbb35247e76e7f6aefa451c974e1b4cce4376cf0e1adfb7a91d5`.
Those immutable trees, signing and notarization records, previous install
journals and user configuration remain preserved. No network setting or
running process is changed by this source allocation.

Source or preflight failures before candidate freeze retain the same
unconsumed build 40070 and use separate attempts. Signing, authentication,
cleanup and publication requirements remain unchanged.
