# Settings

- Launch at login
- Window/tray behavior
- Controller port policy
- Deep-link state
- Migration/import utilities
- Future notarization and helper health diagnostics

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
