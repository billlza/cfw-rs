# General page

The General page presents one authoritative engine state and two mutually
exclusive controls: System Proxy and Tunnel. A requested mode is not displayed
as Active until observed runtime owner, generation, config digest, readiness,
and the relevant macOS status all match.

The legacy Service Mode row is a temporary cleanup-only migration affordance.
It can unregister the retired helper and report an exact cleanup failure; it
cannot install, approve, or start the old root data plane.

Application launch never activates this cleanup path. While the migration is
`awaiting_confirmation`, the existing VPN remains unchanged and the Profiles
page stages the replacement in a directory that legacy cleanup never targets.
The cutover button is enabled only after a replacement profile is selected and
the signed native replacement reports preflight readiness. The server requires
the same explicit confirmation and preflight again before invoking retirement;
renderer state alone cannot authorize a destructive cutover.

Legacy System Proxy and DNS cleanup may require explicit review. The migration
does not assume that a historical snapshot still owns the current macOS
setting, and it does not overwrite a later user or administrator change. New
network modes remain blocked until the UI reports the required proxy/DNS action
as resolved.

Network-path changes mark observations stale and trigger coordinator recovery.
They are not treated as UI-only refresh events. Loading, approval, failure,
awaiting confirmation, cleaning, manual cleanup required, and Off remain
distinct user-visible states.
