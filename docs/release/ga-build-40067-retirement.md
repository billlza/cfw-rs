# Build 40067 dependency successor

Build 40067 was signed, notarized and installed. Its installed application and
frozen worktree remain preserved. The user confirmed normal use before reporting
a transient connection outage on 2026-09-15; that outage has not been attributed
conclusively to either the application or the upstream proxy.

The requested dependency refresh changes product inputs: sing-box 1.14.1,
Rust dependencies, the Go compiler, the Swift/Xcode compiler, and the native
interface observer. These bytes cannot inherit the consumed 40067 identity.
The allocation ledger therefore records 40067 as
`retired_product_change_after_install_before_ga_runtime_acceptance` and allocates
40068 as the active successor.

This is retirement from the release-candidate lineage. It does not stop,
uninstall, overwrite or revoke the installed 40067 application, its frozen
source, signatures, notarization records, profiles or networking state.

40068 needs its own source-bound checks, application build, signatures,
notarization and runtime acceptance before publication. Allocating it does not
consume it; a failed pre-candidate check keeps the same build number. No
permission, ownership, DNS-leak, signing or physical-evidence check is relaxed.
