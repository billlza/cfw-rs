# GA build 40047 retirement

Build 40047 is classified as
`retired_product_change_after_install_before_ga_runtime_acceptance`.
Its signed application was accepted by Apple, stapled, installed and
recommissioned. Public release and OS networking acceptance did not complete.

The installed application preserved the imported PROXY selector and 12 rules.
A production-runtime test using the real selected remote node returned Google
204 and OpenAI 401 responses. These component results do not prove that macOS
System Proxy or TUN was activated.

Two product gates still blocked normal operation. System Proxy rejected any
enabled previous proxy setting instead of taking ownership on the explicit
enable request. Service maintenance also required a restarted Authority to
prove Off before registering the ProxyAgent needed for that proof.

Build 40048 corrects these product paths. Existing proxy values remain in the
ownership journal, application still compares the captured values under the
preferences lock, and restoration changes only protocol groups CFM still owns.
Authority registration reports registration alone. ProxyAgent registration then
uses the normal owner observations and reconciliation to prove Off; an active
lease still blocks maintenance.

Preserve the frozen 40047 checkout, all failed and successful installation
attempts, the original Apple receipt and the signed application tree
`7195dd5922cbf6cf38284c2aba83619cb727c1638f52559add6d780fb853b593`.
40047 is the exact supported predecessor of 40048. Its completed journals use
the frozen 40047 validator and are not reinterpreted as 40048 registration receipts.
