# Connections

- Live connection list
- Per-connection metadata
- Traffic overview
- Close all connections action

The **Connection diagnostics** tab shares this page with the live list. Opening
it sends no requests. **Run checks** observes the system socket path and the
current CFM path, IPv4/IPv6 exits, and HTTP responses from Claude, ChatGPT,
Anthropic and Cloudflare. Addresses start hidden and are not written to logs or
persistent settings. Results carry their observation time.

An owned local proxy uses SOCKS5 with remote DNS; pure TUN uses system sockets.
The system-path label does not claim to bypass a VPN. Failed proxy requests never
retry directly. Mode/identity changes cancel the run, and the engine's existing
intent revision and node selections reject stale results. One request can run at
a time, with a 30-second overall limit, four-second connection limit,
eight-second HTTP limit and 32 KiB response limit. Redirects and retries are
disabled. Cancellation drops the requests; DNS resolver workers retain their
four-slot bound until the OS returns.

Additional checks are explicit actions:

- **IP information** sends the chosen exit address to ipapi.is. The anonymous
  response provides approximate location, ASN, operator and timezone. Unknown
  fields remain unknown. It does not provide trust scores, residential-IP,
  VPN, proxy, Tor or abuse verdicts. Lookups are limited to one per minute in
  this process; a provider 403/429 blocks further lookups for 24 hours.
- **Check DNS** sends four random system DNS lookups to bash.ws and displays
  the resolvers its authoritative collector observed. Failed/empty observations
  are inconclusive. Resolver geography or ASN alone does not prove a leak,
  encryption, or the absence of leaks.
- **Check UDP** gathers server-reflexive UDP ICE candidates through Cloudflare
  STUN, without camera or microphone access. It compares only matching IP
  families against the HTTPS observations. A timeout, unavailable WebRTC, or
  absent candidate never becomes a protection verdict. Other applications and
  browsers can have different routes.

HTTP 2xx establishes endpoint reachability; redirects, authentication, challenges,
rate limits and other failures stay distinct. None proves account access or
regional eligibility. Endpoint-specific trace failures never borrow another
service's exit IP.

Provider contracts: [Cloudflare trace](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/),
[public STUN](https://developers.cloudflare.com/realtime/turn/),
[ipapi.is anonymous data and quota](https://ipapi.is/free-tier.html),
[bash.ws CLI protocol](https://github.com/macvk/dnsleaktest/blob/master/dnsleaktest.sh).

