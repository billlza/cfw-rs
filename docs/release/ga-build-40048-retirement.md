# GA build 40048 retirement

Build 40048 is classified as
`retired_product_change_after_install_before_ga_runtime_acceptance`.
Its application was signed, accepted by Apple, stapled, installed and
recommissioned. The service-registration recovery cycle was closed in that
real installation. Public release and networking acceptance did not complete.

With CFW fully closed, the real System Proxy start reached macOS network
authorization after starting its listener. The five-second RPC deadline then
caused failed-start cleanup while the authorization dialog was still pending.
The Authority subsequently treated an already-quarantined owner's delayed
disconnect as a fatal stale operation. System Proxy never became effective.

40049 requests authorization before submitting an engine mode change. That
bounded user-interaction request acquires no Authority or Host mutation lease
and starts no listener. Runtime transactions check rights without interaction,
retain the Agent's own authorization reference, and never destroy unrelated
shared credentials. Lock acquisition is also checked before entering SCHelper;
it must not open an implicit authorization dialog during process recovery.
Read-only recovery does not require a write grant; settings
already restored in both storage and effective state require no publication.
Repeated revocation retains quarantine and its revision until a real Off proof.

Preserve the frozen 40048 checkout, Apple submission
`09e729aa-74da-4a1d-ab13-f6354b5b0843`, signed application tree
`dad5b7aae1667c8448b0ecfe0dce6956bf8ca9fc1f1767a253d57723b088abe7`,
failed runtime observations, original ownership journals and completed install
records. Those records are not runtime acceptance for 40049.
