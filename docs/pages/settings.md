# Settings

- Launch at login
- Window/tray behavior
- Controller port policy
- Deep-link state
- Migration/import utilities
- Future notarization and helper health diagnostics

## Engine › when its controls are held

The switches of the Engine group and the Configure button of the local proxy
port change the runtime network settings. They are disabled, each with the
reason, until those settings have been read, after a read of them has failed,
and in the window of a legacy maintenance session, which owns the network. A
failed read is the page's own or the one that a click on a switch, on
Configure or on Reload From Disk makes. When answers arrive out of order, the
page shows settings only from the answer to the last thing it asked: it asks
again because something may have changed, and a write that ended since has
settings of its own. A failed read counts unless the answer to something the
page asked later is already in, whether or not the page shows that answer,
and it holds the controls until the page shows settings again. Reload From
Disk reads the network settings again as well as the preferences, so controls
that a failed read holds can be tried again without reloading the dashboard.
A switch that is held in the window of a session still shows a setting that
was read. Before the first read and after a failed one a switch is drawn off,
because its value is not known, and the reason beside it says that, in the
window of a maintenance session as well. The General page holds its controls
of the same settings in the same way. The window that starts a maintenance
session is not held: it closes once the session's window is ready.

## Engine › Mainland China direct

Off by default. It is a runtime setting, saved in `cfw-runtime-settings.json`
and applied through the same transaction as the other network settings: a
running core is replaced by a candidate, and a candidate that fails to start
leaves the setting unchanged while the app restores the previous core, unless
the candidate's engine cannot be closed.

In Rule mode it adds three routes after the selected profile's own rules and
before its final outbound, so a profile's rules always take precedence:

1. GeoSite `cn` goes DIRECT;
2. GeoSite `geolocation-!cn` goes to the profile's final outbound, matched by
   name. The switch adds no lookup for it, but a profile that resolves names
   itself still does: each of its IP or GEOIP rules without `no-resolve`
   resolves first, and with a nameserver policy or fallback filter every
   route, this one included, does;
3. any other name is resolved, and goes DIRECT when the address is in GeoIP
   `CN`.

For a profile without its own `dns` (an outbound-only file has none; a Clash
profile imported with a `dns:` section has one), mainland names in Rule mode
are resolved by DNS-over-HTTPS in mainland China, dialled directly (AliDNS
`223.5.5.5`, then DNSPod `1.12.12.12`), and the app's proxied resolvers become
Cloudflare `1.1.1.1`, then Google `8.8.8.8`, because a mainland resolver
reached through a foreign proxy still answers blocked names with censored
addresses. These DNS changes apply only to such profiles: a profile's own `dns`
is never changed. Global and Direct modes route as before, but the resolver
change applies in every mode while the switch applies: the proxied pool is
Cloudflare, then Google, and DIRECT connections resolve through the DNS rules.

The switch is one global setting, but whether it applies is decided per
profile: only a profile whose selected route is remote uses it. With any other
profile, for example one whose final outbound, or the node chosen in its final
group, is DIRECT, the switch has no effect at all, on routes, DNS or
downloads, although it still shows as on. A final group that tests or
balances its members (url-test, fallback, load-balance) counts as remote only
when every member is remote, so one DIRECT or REJECT member turns the switch
off for that profile. The three datasets are rule sets downloaded through the
remote route, synchronously, during the first start with each profile,
separately for System Proxy and Tunnel, and refreshed daily while the core
runs. That start must finish within 11 seconds of reaching the ProxyAgent or
the tunnel extension, or it is interrupted and fails with "The engine did not
finish starting in time". When macOS takes several seconds to launch the tunnel
extension, as it can on the first start after installing it, Tunnel reports a
timeout of its 20-second readiness wait instead. A download that fails, for
example because the route refuses it, fails the start too: System Proxy then
reports that its runtime could not be started, and Tunnel reports that readiness
timeout. If the engine cannot be closed after any of these failures, the start
reports instead that global cleanup could not be proven, and neither System
Proxy nor Tunnel starts again until the network is proven Off; turning the mode
off proves it once the ProxyAgent or the tunnel extension has ended (see
General). In Tunnel mode,
connections stall until that start ends, because macOS already routes traffic
into the tunnel. Datasets that finished are cached, so the next attempt
downloads only the rest; a dataset that cannot download within the limit on that
route never will. Turning the switch off removes the dependency. Offline latency
tests never include it.

The GeoSite routes match the destination's name, which System Proxy
connections carry. Tunnel connections carry only the address unless the
profile uses fake-IP, so in Tunnel mode mainland traffic is matched by the
GeoIP `CN` route after the app's DNS has answered; the profile's own domain and
GEOSITE rules cannot match there either.

Trade-offs:

- a direct connection to a mainland address reveals the user's own address and
  the time to that host, including hosts that pages loaded through the proxy
  reference, which usually also learn the page; for browsing that must never
  leave the proxy, turn on Tunnel and then use Global mode, because System Proxy
  alone leaves apps that ignore it, and a browser's WebRTC, on the direct path;
- the datasets come from SagerNet's sing-geosite and sing-geoip releases, the
  same sources as profile GEOIP and GEOSITE rules;
- with rule sets in use, sing-box's routing cache also restores the last proxy
  mode and group selections for the profile, as for any profile with rule
  sets;
- whether the switch applies is decided when the core starts with the
  profile: choosing DIRECT in the final group while the core runs keeps the
  switch's rules until the next start, and the proxied resolvers (Cloudflare and
  Google) are then dialled directly, which mainland networks may block;
- an earlier build refuses a settings file saved with the switch on and does
  not start the core; turn the switch off before installing one.

## Engine › DNS leak protection

Off by default. It is a runtime setting, saved and applied like Mainland China
direct: through the network settings transaction, with the same rollback when
a candidate core fails to start.

In TUN Mode the core already hijacks every port 53 flow into its own DNS,
which for a profile without its own DNS policy is DNS-over-HTTPS through the
selected route, so plain DNS never reaches the network's resolvers. The switch
adds one route rule, right
after that hijack and before the mode rules, so it holds in Rule, Global and
Direct mode alike: every connection to port 853, the port DNS over TLS
(RFC 7858) and DNS over QUIC (RFC 9250) use, is refused with a reset. An app
or a system setting that carries its own encrypted resolver therefore fails at
once and falls back to plain DNS, which is hijacked. The rule applies to every
connection the core handles in TUN Mode, those of the System Proxy and LAN
listeners included when they run beside the tunnel, whatever the selected
route, a profile routed DIRECT included.

What it does not cover:

- DNS over HTTPS shares port 443 with ordinary traffic and cannot be told
  apart without a list of resolvers, so a browser's own secure DNS still
  reaches its provider, through the selected route;
- a profile's own DNS policy: a profile that declares `dns` resolves through
  the servers it declares, plain or encrypted, direct or through the route,
  exactly as declared;
- a query that leaves outside the tunnel's route coverage, such as one scoped
  to a LAN interface whose resolver is a private address, because the
  projection does not change what the tunnel captures;
- the plain lookup of a proxy server's own host name before the core can
  reach it, through the bootstrap servers; a server named by address needs
  none;
- System Proxy and Local Proxy mode, where the app never writes the system
  DNS and the switch changes nothing;
- release evidence projections, which never carry it.

## Engine › WebRTC leak protection

Off by default. It is a runtime setting, saved and applied like DNS leak
protection: through the network settings transaction, with the same rollback
when a candidate core fails to start.

A WebRTC client asks a STUN server which address its UDP packets arrive from,
and a page reads the answer from the candidates it gathers. The page names the
server, so the answer follows the server's route and not the page's. In Rule
mode a page loaded through the proxy can name a server that is routed directly
and read the real address, and a page loaded directly can name a proxied
server and read the proxy's exit.

In TUN Mode the switch adds three route rules. The first recognises STUN
(RFC 8489) by its message format, on UDP only and with the STUN sniffer alone,
so no TCP connection waits for it and no other protocol is inspected. The
second refuses what the first recognised. The third refuses UDP to the seven
ports the core never inspects (25, 110, 143, 465, 587, 993 and 995: it takes
them for mail ports where the server speaks first), because the page names the
server's port too and a STUN server there would go unrecognised. STUN is
therefore given no route at all, and neither address is reported. The rules
follow the Direct mode rule and precede the Global mode rule and the profile's
rules: they hold in Rule and Global mode, whatever the selected route, and
leave Direct mode alone, where every site already sees the real address.

What it costs:

- every app's STUN is refused, not only a browser's. WebRTC also tests each
  peer-to-peer path with STUN, so a call, a game or a remote desktop that
  connects two peers directly goes through its service's relay instead, which
  can be slower, or does not connect when the service offers none;
- TURN (RFC 8656) shares the STUN message format, so a relay allocation over
  UDP is refused too, and a client falls back to a relay over TCP or TLS;
- UDP to the seven mail ports is refused whatever it carries. No standard
  service uses UDP there;
- a page that waits for candidate gathering to finish may wait for the STUN
  timeout first.

What it does not cover:

- System Proxy and Local Proxy mode: a browser sends WebRTC's UDP from the
  network interface, never through an HTTP or SOCKS proxy, so the core does
  not see it and the switch changes nothing. Use TUN Mode there, or the
  browser's own setting (the Chromium policy `WebRtcIPHandlingPolicy` with
  `disable_non_proxied_udp`, or Firefox's
  `media.peerconnection.ice.proxy_only_if_behind_proxy`);
- an address the browser reads from the Mac's own network interfaces rather
  than from a server. Browsers hide these behind generated names until a page
  has camera or microphone permission; after that the page sees them, a
  public IPv6 address included. No route rule can change that;
- a packet that leaves outside the tunnel's route coverage, such as one a
  client sends from a socket bound to a physical interface, because the
  projection does not change what the tunnel captures. Connections ›
  Connection diagnostics › Check UDP reports an exit it observes while the
  switch is in force;
- STUN that is not the first datagram of its UDP session. The core inspects
  the first datagram only. A WebRTC socket opens with STUN, so a browser is
  always recognised; a program that sends something else first from the same
  socket keeps its route for whatever follows;
- split routing itself: in Rule mode a site with servers on both routes
  still sees both exits, through WebRTC over TCP (a relay, or a TCP
  candidate) or through any request that is routed directly. Only Global mode
  sends everything one way;
- release evidence projections, which never carry it;
- an earlier build refuses a settings file saved with the switch on and does
  not start the core; turn the switch off before installing one.

## Engine › TCP concurrency

On by default. It is a runtime setting, saved and applied like WebRTC leak
protection: through the network settings transaction, with the same rollback
when a candidate core fails to start. It is the one switch that rests on:
`cfw-runtime-settings.json` names it only while it is off.

A name often has several addresses. Without the switch the core dials them
one after another, and moves to the next address only when the one before it
has failed; an address that never answers costs the whole connection timeout
first. With the switch the core dials the addresses at once and keeps the
first connection that opens. It cancels the other attempts and closes a
connection that one of them still completes.

It applies to the TCP connections the core opens itself, in every mode:

- to a proxy server named by a domain;
- to a destination that goes direct: in Direct mode, by a rule, or through a
  group set to DIRECT. A System Proxy or Local Proxy connection names its
  destination, which the core resolves. A Tunnel connection carries the one
  address its app chose, unless the profile uses fake-IP, so there is nothing
  to race;
- to a DNS server of the profile that is named by a domain and reached
  directly.

A latency test, and the health check of an automatic group or of a provider,
connect to a proxy server the same way, so they measure what a connection
gets. That holds while the core is off as well: the test then runs in a
separate engine, which takes the switch with the profile.

What it leaves as it was:

- the order of the address families. The family of the first address
  starts, and the other follows when the first has failed or after 300 ms.
  The switch races the addresses within a family, at most eight at a time;
  a further address starts when one of the eight has failed. An address
  that an answer or a hosts file names more than once is dialled once;
- a connection carried through a proxy, which the proxy server opens, and
  the connection to a node that is reached through another node;
- UDP;
- a DNS server reached through the selected route or the route rules, and
  the app's own DNS servers, which are dialled by address;
- a name with one address.

What it costs: a server with several addresses sees an attempt on each of
them where it saw one, and every attempt but one is dropped at once.

Notes:

- a Clash profile's own `tcp-concurrent` key is not read, like the other
  top-level keys of the document that tune a client. The switch decides;
- release evidence projections carry the switch like any other projection,
  so release evidence is taken with the dialing the release ships;
- an earlier build refuses a settings file saved with the switch off and
  does not start the core; turn the switch on again before installing one.

## Background controls › Automatic subscription updates

Off by default. The interval (every 6 or 12 hours, every day, every week) is
stored in `cfw-subscription-settings.json`, apart from the preferences and
from the runtime and automation settings, so an earlier build never reads it.
A stored value this build does not know leaves updates off and disables the
setting, which then shows the reason.

While the app runs, a subscription is due one interval after its profile was
last saved. The app looks for due subscriptions one minute after launch, every
five minutes after that, and at once when the interval changes. Each one is
downloaded and validated exactly as Update on the Profiles page does it, one
after another: through the running core's local proxy port when it has one,
and otherwise directly.

What happens to a download depends on what the core runs:

- the core is off, or runs another profile: the download replaces the stored
  profile and keeps the manual node choices that still exist, as an update by
  hand does;
- the core runs this profile and the download is the document it already
  runs: the profile is saved again, which only renews its saved time;
- the core runs this profile and the download differs in its nodes, rules or
  credentials: nothing is changed. The stored profile, the Keychain and the
  running core stay as they are, and the profile's card on the Profiles page
  says that new content is available. Apply update downloads it again and
  restarts the core onto it, as Update does. Once the core is off or runs
  another profile, the next look replaces the profile by itself.

A background update never starts, stops or restarts the core and never asks
macOS for authorization. It is not a new mode request either, so network rules
and a running connection diagnostic go on as before. It takes its turn with
mode and profile changes; while maintenance holds the engine, it is left for
the next look.

A failed attempt leaves its reason on the profile's card and is repeated after
half an hour, or after one interval when that is shorter. A waiting change is
downloaded again after one interval for as long as the core keeps running the
profile. What the cards show is kept in memory only: after a restart the
schedule starts again from each profile's saved time. Updating a profile by
hand, or changing its name or address, clears its note at once; saving it in
the editor clears it at the next look. Turning updates off clears every note
and ends the look that is under way: a download that ends after that is
neither saved nor noted, while a save that has already begun is completed.
Choosing another interval ends that look in the same way, and the look that
follows at once downloads again what is still due.

A failure is noted only while the profile is still stored exactly as it was
when its download began. Once the profile was updated by hand, edited,
renamed, given another address or deleted meanwhile, no failure is noted, and
a document downloaded from the previous address is not saved. A profile that
was updated, edited, renamed, made local or deleted after a look began and
before its own turn is skipped in that look. The next look decides about the
profile as it is then.

Limits:

- nothing is updated while the app is not running;
- the saved time of a profile is the time of its last update, not of its last
  change, so a subscription whose content never changes is still downloaded
  once per interval;
- a provider that writes changing information into node names, such as the
  remaining traffic or an expiry date, changes its document with every
  download. A profile the core does not run is then saved anew every
  interval, and the card of the running profile says that new content is
  available just as often;
- while a start of the core has failed or waits for approval, the selected
  profile counts as the running one: a changed download waits on its card,
  and one that equals it is reported as failed, as an update by hand is,
  until the core is switched off or recovers;
- credentials an update no longer references stay in the Keychain until
  Settings › Credentials › Unused credentials removes them, as after an update
  by hand;
- a profile opened in the editor before a background update replaces it is
  refused on Save, because it is no longer the stored document.
