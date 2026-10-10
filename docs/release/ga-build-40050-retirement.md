# Build 40050 startup recovery correction

40050 completed Developer ID signing, Apple notarization, stapling, Gatekeeper
assessment and local installation on 2026-09-09. Its frozen source, signed
application and receipts remain preserved. No public release completed.

The installed application reported `query_status: InvalidMessage`. Read-only
diagnostics found 23 valid journal frames ending at revision 23 with state
`quarantined` and transition `reconcile_off`. The lifecycle writes this record
when cleanup proof is incomplete, but startup classified it as an invalid
state. The storage recovery then discarded the trusted cursor, and the
snapshot schema rejected the resulting cursor-less quarantine.

40051 treats a validated durable `quarantined/reconcile_off` record and its
compacted checkpoint as requiring owner cleanup reconciliation. It retains the installation, epoch,
generation and revision, recreates no executable lease, and still requires
both owner domains plus the managed tunnel to prove Off. Corrupt journals,
missing anchors, incomplete evidence and other invalid transitions remain
blocked. No production record or Keychain anchor is reset.

Swift and Rust snapshot schemas now consistently represent cursor-less Off
or recovery failure and a quarantined revoked lease. Active ownership still
requires a cursor and lease; a revoked lease also requires its cursor.
Shared wire fixtures and real descriptor-relative journal restart tests cover
these states and rejection of every missing cleanup proof.

The application bytes change, so 40050 is recorded as
`retired_product_change_after_install_before_ga_runtime_acceptance` and 40051
is the successor. This is not a rebuild for a test or evidence-only change.
