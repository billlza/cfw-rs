# General page

The General page presents one authoritative engine state and two mutually
exclusive controls: System Proxy and Tunnel. A requested mode is not displayed
as Active until observed runtime owner, generation, config digest, readiness,
and the relevant macOS status all match.

Green switches represent observed activity. Failed requests and requests waiting
for approval stay unchecked and have separate retry and cancellation actions.
The exclusive mode model is a known CFW compatibility gap, documented in the
[compatibility audit](../cfw-compatibility-audit.md).

The legacy Service Mode row is a temporary cleanup-only migration affordance.
It can unregister the retired helper and report an exact cleanup failure; it
cannot install, approve, or start the old root data plane.

Application launch never activates this cleanup path. Older CFM maintenance is
an explicit Settings action. Normal networking is independent of an untouched
legacy installation; unfinished maintenance transactions still require their
own recovery. Profiles are stored in a directory legacy cleanup never targets.
Explicit maintenance requires a selected replacement and native preflight
before destructive retirement; renderer state alone cannot authorize cleanup.

Legacy System Proxy and DNS cleanup may require explicit review. The migration
does not assume that a historical snapshot still owns the current macOS
setting, and it does not overwrite a later user or administrator change. An
existing enabled system proxy is a separate activation conflict, with its own
error; it is not a malformed profile and is not evidence that every other
startup failure was caused by the old app.

Network-path changes mark observations stale and trigger coordinator recovery.
They are not treated as UI-only refresh events. Loading, approval, failure,
awaiting confirmation, cleaning, manual cleanup required, and Off remain
distinct user-visible states.
