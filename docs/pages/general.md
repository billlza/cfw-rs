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

When an engine cannot be closed, after a failed start or at a stop, the app
reports that global cleanup could not be proven. So does a close still
unfinished 2 seconds into a stop, and an interrupted start still inside the
engine 5.5 seconds after its deadline. The ProxyAgent or the tunnel extension
then ends itself, so macOS releases the ports and connections the engine still
held. The ProxyAgent first restores the system proxy settings it changed, and
it waits until it has run 11 seconds, so macOS can start it again at once. If
it cannot restore them, it keeps running and tries again whenever you approve
the macOS password prompt that turning System Proxy off and quitting the app
show; after the Mac restarts, quitting the app shows that prompt to restore
them. The tunnel extension ends once macOS has stopped the tunnel, or 2
seconds after its report when macOS does not. Neither System Proxy nor Tunnel
can be turned on again until the network is proven Off. Once the ProxyAgent or
the extension has ended, turning the mode off proves it, without restarting the
Mac. Until the network Authority restarts, as it does when the Mac restarts,
only the app of the user who turned System Proxy on, signed in at the console,
can prove its settings restored.

The GeoIP Database row lists the selected profile's GEOIP countries and, when
Settings › Engine › Mainland China direct is on, names that switch first.
Before the runtime settings are first read, and after a reload of them fails,
the switch's state is unknown: the row then lists only the countries, or says
unavailable when there are none, instead of reporting that no country rules
exist. While the selected profile's saved policy is loading or cannot be read,
its countries are unknown: the row names only the switch when it is known to be
on, and otherwise says unavailable.
