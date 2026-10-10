# Build 40070 bounded-startup successor

Build 40070 was signed, notarized, stapled and installed. On a supported
ARM64 MacBook Air with an M5 processor, opening the application could leave a
black, unresponsive dashboard. Repository analysis found reachable startup
paths that displayed the window before the renderer had painted and allowed
SystemConfiguration, Keychain and cross-process file-lock waits to remain
unbounded. The available report does not prove that any one of those waits was
the sole device-specific cause.

The correction hides the initial window until a static startup surface exists,
paints verified identity before optional reads, isolates network diagnostics,
and bounds Keychain plus settings, profile, lineage and migration lock waits.
These changes alter shipped Host and UI bytes and therefore require successor
40071. The allocation ledger records 40070 as
`retired_product_change_after_install_before_ga_runtime_acceptance`. This does
not claim that 40071 has passed installed M5 startup or broader runtime and
publication acceptance.

The installed and frozen 40070 application trees were independently measured
and match SHA-256 tree v2
`9adab1e77ce478799253e7fa5fc9e0314e2ee2b9b5a8ec8830782fcbb1b9e03f`.
The frozen source commit is
`ec650f66fe7f8964b335fe86a540ff88d2631e84`. Those immutable trees, signing and
notarization records, installation journals, user configuration and registered
service history remain preserved. This source allocation itself changes no
running process or operating-system network setting.

Source, CI or preflight failures before candidate freeze retain the same
unconsumed build 40071 and use separate attempts. Once 40071 is frozen, only
its exact supported recovery paths may reuse that build identity.
