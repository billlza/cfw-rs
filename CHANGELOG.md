# Changelog

## 0.5.1 - Unreleased

### Profiles

- Add the `tailscale` node. The Mac joins a tailnet with an auth key kept in
  the credential vault and sends the traffic routed to the node through one
  exit node (`exit_node`), with optional `control_server` (an https URL, for
  Headscale), `hostname`, `accept_routes` and `exit_node_allow_lan_access`.
  The node never advertises routes or an exit node, runs no Tailscale SSH
  server and takes no Taildrop, in the profile and at import; a sing-box node
  list's `endpoints` entry imports with its `auth_key` moved into the vault.
  Each runtime keeps the node's state under its own working directory, so use
  a reusable auth key, and the latency test measures the node only while the
  core runs its profile. Earlier releases reject profiles that carry the node.

### Reliability

- Give every node of a latency test its whole timeout. The engine a test
  starts was held to the same deadline, so a large profile tested at a short
  timeout on a busy Mac could fail as a whole while that engine was still
  starting. The timeout now runs from when the engine has started.

### Supply chain

- Build the network engine from sing-box 1.14.4 instead of 1.14.2. The Go
  modules it requires directly move to their newest releases, among them
  `golang.org/x/crypto` 0.58.0, `golang.org/x/net` 0.61.0, gRPC 1.84.0 and
  uTLS 1.8.8; sing-box's own modules stay at the versions released with it.
- Build with Rust 1.99.1 instead of 1.98.1. Release builds accept only that
  exact toolchain.
- Move the Rust crates to the newest releases their requirements allow,
  among them tokio 1.54.1, hyper 1.12.0, uuid 1.29.0, and the Tauri runtime
  2.12.2 with wry 0.57.1. Crates pinned to an exact version, Tauri 2.12.0
  among them, are unchanged.
- Build the network engine with `with_tailscale` and the `ts_omit_*` tags of
  the upstream Apple client, which leave out the Tailscale log upload, SSH
  server, Taildrive, Taildrop, web client and platform integrations the Mac
  never uses.

## 0.5.0 — 2026-10-17

### Interface

- Use native SwiftUI components in the existing interface, preserving the
  page layout, settings handlers and network controls: the Profiles menu, the
  Network settings form, the General switches, and the profile deletion,
  settings reset and information prompts.
- Refresh only the status bar of the General page when connection updates
  arrive. The page is no longer rebuilt once a second while the core runs.
- Draw the window as Liquid Glass: the window is transparent with its title
  bar hidden, and a native backdrop under the page carries the glass slab, the
  frosted sidebar and workspace panels, the sidebar cards and the selected
  navigation item at the rectangles the page measures. The page keeps its
  layout and texts, shows glyphs beside the navigation labels and its slogan
  beside the header, and paints its own backgrounds whenever the host does not
  show the glass. The transparent WebView uses Tauri's macOS private API.
- Show the engine's own version string on the General page, keep the
  Connections and Logs toolbars on one line or wrap them whole instead of
  squeezing their labels, and use the ordinary hint colour for the Profiles
  import note.

### Reliability

- Keep the automatic proxy and controller ports, 7890 and 9090 by default,
  when switching from TUN to System Proxy or Local Proxy. The tunnel's engine
  runs as root, and the connections it had just closed kept those ports
  reserved against the user's proxy agent for about thirty seconds, so the
  switch failed several times and then moved to 7891 and 9091 without saying
  so, breaking shells and tools set to the old port. The engine's loopback
  listeners now let the agent take the same port back at once, while a port
  that is still being listened on stays refused.
- Read the process table on macOS 27, where `ps` prints the `nobody` user's
  uid as `-2`. Starting the core, saving runtime settings and recovering
  background services no longer fail on such a row.
- After an installation or update, the dashboard asks for background service
  recovery by itself a few seconds after launch and, if that still fails,
  explains the steps to take instead of showing the raw reason.
- Keep a running core published while its status reads miss: a read that
  times out, finds a busy authority or an unavailable service is retried for
  three polls before the page says anything, the page then explains that the
  core's state is being confirmed instead of calling it failed, and the
  attested runtime returns on the next exact observation. A busy or unanswered status read at
  launch is re-observed by the dashboard's own recovery like an unproven
  cleanup. Mode switches prove the global Off barrier with the operation
  deadline instead of the two-second poll deadline.
- Retry an automatic proxy port once in place before moving to the next
  candidate: the listener a mode switch just stopped may still be closing, so
  the port no longer drifts from 7890 after switching System Proxy or TUN.
- Say what to do when System Proxy authorization times out or is cancelled:
  turn the switch on again and approve the macOS prompt.
- Refuse a Reality node without a uTLS fingerprint when it is imported or
  saved, naming `outbounds[N].tls.utls`, instead of storing a profile the core
  then cannot start. The Clash `client-fingerprint` (or the document's
  `global-client-fingerprint`, below), link `fp` or sing-box `tls.utls` must
  name one; the app never picks one for the node. A profile an earlier
  build stored with such a node is listed as invalid, as below.
- List a stored profile that fails the current validation on the Profiles page
  as invalid, with the validator's message, instead of failing the whole
  profile list. Other profiles can still be imported, selected, started and
  deleted. An invalid profile cannot be selected or started and nothing is
  chosen in its place; while it is selected, System Proxy and TUN refuse with
  its message. Delete removes it, and deleting the selected one needs the
  core stopped and leaves no profile selected. A subscription's card shows its
  URL on request so it can be imported again first. Credential cleanup is
  refused, naming the invalid profiles, until they are deleted. Corrupt,
  unsafe or digest-mismatched entries still block the profile list as before.
- Honour a Clash document's top-level `global-client-fingerprint` as Mihomo
  did until v1.19.27 removed it: a TLS VMess, VLESS (Reality included),
  Trojan or AnyTLS node without a non-empty `client-fingerprint` of its own
  gets that uTLS fingerprint, so such Reality nodes import again. Earlier
  builds ignored the key, so updating such a subscription switches those
  nodes from standard TLS to the named browser ClientHello. A node's own
  value wins, and `client-fingerprint: none` now keeps standard TLS instead
  of failing the import. A global `none` or empty value sets nothing; any
  other value the app does not support fails the import and names the key.
  HTTP, Hysteria2 and TUIC nodes never take it, and a V2Ray QUIC node that
  would take it fails like an explicit fingerprint there. Proxy providers
  store the value so refreshing them applies it again; a profile that stores
  it cannot be loaded by an earlier build, and providers imported before
  this version keep standard TLS until the subscription itself is updated.
- Importing typed profile JSON (nodes with `credential_ref`) whose fields are
  well formed but fail validation, such as Reality without uTLS, names the
  field and the reason, as saving it in the profile editor does, instead of
  reporting that the JSON does not match the sing-box node-list schema.
- Connect to Reality servers that require the post-quantum X25519MLKEM768 key
  share, as Xray releases from v26.9.8 do. A node opts in with Clash
  `reality-opts.support-x25519mlkem768: true` or sing-box
  `tls.reality.support_x25519mlkem768: true`; the `chrome` uTLS fingerprint is
  then required, because only its hello carries that share. The option is off
  by default because older servers may mishandle the hybrid share. A profile
  saved with it is rejected by earlier builds, which do not know the field.
- Import the Hysteria2 options of the sing-box 1.14 runtime: a randomized hop
  interval (Mihomo or link `hop-interval: 15-30`, sing-box `hop_interval_max`),
  gecko obfuscation with optional packet-size bounds, and a BBR profile that
  cannot be combined with an upload rate, which would select Brutal. A hop
  interval under five seconds, which the runtime never dialed, now fails
  import, and a stored profile with one is listed as invalid. Profiles saved
  with the new options are rejected by earlier builds.
- Import a Clash node's `ech-opts` with an inline base64 `config` as ECH with
  TLS 1.3. A node without one, which Mihomo would look up over DNS, and
  `query-server-name` fail import instead of sending a plaintext ClientHello.
- Import Clash `GEOSITE` rules, including in classical rule providers, as
  site-category rule sets named as SagerNet/sing-geosite publishes them
  (`google@!cn` included). Such profiles were refused before. A profile may
  name at most 256 distinct GeoIP and GeoSite datasets, and a DNS selector
  naming a dataset that cannot exist now fails at import instead of at engine
  start. Profiles saved with GEOSITE rules are rejected by earlier builds.
  Each GeoIP and GeoSite dataset is downloaded during the first start with the
  profile, separately for System Proxy and TUN, and that start must finish
  within about 11 seconds (see the bounded engine start below), so with many
  datasets or a slow route it may fail; datasets that finished are cached, so
  a retry downloads only the rest. A GEOSITE name that only Mihomo's MetaCubeX
  datasets publish imports, but its dataset cannot be downloaded, so every
  start with the profile fails.
- A stored profile whose DNS `geosite` selector names a dataset in a form
  sing-geosite never publishes (for example with `_`, a leading `!`, `-` or
  `@`, more than one `@`, or an empty or malformed attribute after `@`), which
  could never download, or that names more than 256
  distinct GeoIP and GeoSite datasets, now fails validation when it is loaded
  and is listed as invalid, as above.
- Add Settings › Engine › Mainland China direct, off by default. In Rule mode
  it sends mainland China destinations that no profile rule matches DIRECT
  (GeoSite `cn`, then GeoIP `CN` after a lookup; GeoSite `geolocation-!cn`
  keeps the profile's final route), and for profiles without their own DNS
  policy it resolves mainland names through DNS-over-HTTPS in mainland China,
  dialled directly, while other names use Cloudflare and Google through the
  proxy. It applies only when the selected route is remote. Its rule sets
  download through that route during the first start with each profile, which
  must finish within about 11 seconds; while they cannot be downloaded in time
  the start fails, the setting is left unchanged, and the app restores the
  previous core unless the failed engine cannot be closed. In TUN, without
  fake-IP, mainland traffic is matched by GeoIP after the app's DNS answers.
  General names the switch in its GeoIP Database row. Earlier builds refuse a
  settings file saved with it on, so turn it off before installing one.
- Bound every engine start, System Proxy and TUN alike, at 11 seconds from
  the moment the ProxyAgent or the tunnel extension receives it. Uncached rule
  datasets download inside the start and had no time limit of their own: a
  System Proxy start that downloaded for more than 5 seconds outlasted the
  app's wait for the ProxyAgent and failed, and past about 10 seconds the
  rollback could not stop the engine that was still starting, so the network
  Authority quarantined the start until the Mac restarted. A TUN start
  that stalled the same way met the same rollback after its 20-second
  readiness wait. Such a start is now interrupted, even while the engine is
  still being built from a large profile, and fails with "The engine did not
  finish starting in time"; datasets that finished are kept, so a retry
  downloads only the rest, while one that cannot download within the limit on
  that route never will. The app waits up to 18 seconds for the ProxyAgent's
  start reply. A TUN start that times out is reported as soon as the
  extension stops instead of after the 20-second readiness wait, unless macOS
  took several seconds to launch the extension, as it can on the first start
  after installation; that start still ends in the readiness timeout. A user
  switch, sign-out or lost Authority connection during a start still waits for
  the start to end and can still quarantine it.
- Let the engine close after a start that failed before it began watching the
  network, for example because its cache file could not be opened. Closing
  failed, so the ProxyAgent or the tunnel extension could neither stop nor
  start the engine again until it was restarted.
- When libbox cannot close an engine, after a failed or interrupted start or
  at a stop, the ProxyAgent or the tunnel extension now reports it and ends
  its process, so macOS releases the listeners, connections and descriptors
  that close left open. libbox closes an engine only once, so retrying the
  close could never succeed, and what it left open stayed open while the
  process ran. A close still unfinished 2 seconds into a stop, and an
  interrupted start still inside the engine 5.5 seconds after its deadline,
  count the same: they no longer hold every later reply and stop without
  end. The ProxyAgent ends only once it has restored the system proxy
  settings it changed, and no sooner than 11 seconds after it started, so
  macOS starts its successor at once instead of holding the app's next
  requests for up to 10 seconds. While it cannot restore them it keeps
  running, and tries again whenever the macOS password prompt that turning
  System Proxy off, quitting the app and recovering background services show
  is approved; after the Mac restarts, that prompt also restores what an
  earlier ProxyAgent left. The
  extension ends once it has answered the stop that macOS asks for after
  receiving its report, or 2 seconds after the report when macOS asks for
  none, and it refuses every start until then; a failure during a stop macOS
  asked for is reported with that stop's answer. The failure is reported as
  "Global cleanup could not be proven", also by a System Proxy or Local Proxy
  stop, which reported a rejected configuration, and by a Tunnel start as soon
  as the extension reports it rather than after the 20-second readiness
  timeout, unless macOS has not received that report when the extension
  ends. The network Authority then accepts no start until cleanup is
  proven. Once the ProxyAgent or the extension has ended, it releases the
  start as its restart would, so turning the mode off proves the network Off
  again instead of having to wait for the Mac to restart. Until the network
  Authority restarts, as it does when the Mac restarts, only the app of the
  user who turned System Proxy on, signed in at the console, can prove its
  settings restored. After such a restart another user's app can prove the
  network Off, but it cannot start the network itself (see Known
  limitations), and settings the first user's System Proxy left can still
  point at its closed port until that user approves the prompt again, or an
  administrator clears them.
- A profile check whose engine instance cannot be closed now fails with an
  error that may be retried, instead of passing while the instance stayed in
  the ProxyAgent; every proxy, group and inbound the app writes closes. A
  profile check or latency test whose engine panics while closing fails
  instead of ending the ProxyAgent.
- A profile check or offline latency test that hangs inside the engine no
  longer holds the ProxyAgent's other replies, nor leaves it unable to check
  or test until the Mac restarts. A check answers within 3.5 seconds and a
  latency test within 3.5 seconds beyond its timeout, with an error that may
  be retried, so a check that takes between 3.5 and 5 seconds, which passed
  before, now fails with that error, and keeps failing on a Mac that always
  takes that long for the profile; the largest profile the app writes checked
  in about a second on the development Mac. One still running 30 seconds
  later counts as hung, and a check or latency test whose instance could not
  be closed counts the same: the ProxyAgent then refuses checks, latency
  tests and starts with an error that may be retried, keeps a running System
  Proxy until it is turned off, then ends, and macOS starts a fresh one. A
  ProxyAgent whose engine could not be closed refuses checks and latency
  tests too.
- Turning System Proxy off restores the network settings before the engine
  stops. If macOS does not take them, System Proxy keeps running and can be
  turned off again, instead of leaving the Mac's proxy settings pointing at
  127.0.0.1:7890 with nothing listening there, which cut off every app that
  uses them. Once the settings are restored the engine stops even when the
  network Authority cannot order the stop yet, and turning System Proxy off
  again finishes it. A ProxyAgent from before an update, or one whose
  version the app cannot verify, stops as it did. A stop the system forces,
  at a user switch, a sign-out or a lost Authority connection, and the
  clean-up after a failed start still stop the engine even when the settings
  cannot be restored.
- Turning System Proxy off after its engine stopped on its own while its
  settings could not be restored completes once the macOS prompt is approved,
  instead of failing, and holding back every start, until the user signs out
  or the Mac restarts.
- A ProxyAgent that has to end, because its engine could not be closed, its
  stop was quarantined or a check left the engine stuck, no longer cuts off
  answers it still owes, such as a password prompt being answered or a
  check: it ends once every request it received is answered, waiting at most
  as long as the app waits for that prompt.
- Recover background services first shows the macOS password prompt when an
  ended System Proxy left its settings behind, and restores them; cancelling
  the prompt or leaving it unanswered ends the recovery with a message saying
  so. With nothing left to restore it shows no prompt.
- Turning System Proxy off after the network Authority restarted completes
  instead of failing every time until the app is relaunched: the ProxyAgent
  asks the Authority about its own lease and, once the Authority says it no
  longer holds it, finishes the stop as Off. The Authority answers only about
  the asking ProxyAgent's own lease, checked against the connection's
  identity, and says it is not ready, rather than that the lease is gone,
  until it has read its journal. A ProxyAgent whose stop the Authority
  quarantined ends after its reply, so the Authority can lift the quarantine
  once it sees that process end, and one whose stop failed for want of the
  restore rights completes it once the prompt is approved.
- A stop that waited while another copy of the app started the network again
  no longer fails, and blocks every start, until the app is relaunched: once
  the network Authority has moved past that stop's generation, the stop ends
  as soon as its own engine is Off. While another user's app holds the
  network, the status reports it busy, which a later read settles, instead of
  a rejected identity.
- Report owner failures by their own meaning instead of as a rejected
  configuration when they are no fault of the profile. A network Authority
  error that the ProxyAgent passed on broke its reply, so the app reported it
  as unavailable; it now reports the Authority's own error. A failure the app
  does not know reports an internal error, or unavailable when it may be
  retried; one whose retry flag contradicts its code, or a stop for another
  generation than the one the ProxyAgent runs, reports a rejected identity; a
  start or stop that overlaps another reports busy; an engine slot, process
  boundary or request the owner cannot take reports an internal error; an
  invalid tunnel start ticket reports an invalid ticket, a tunnel extension
  that cannot reach the network Authority reports that, and a tunnel status
  the app does not know reports unavailable; and a System Proxy listener that
  never became ready reports a runtime failure.
- A System Proxy or Local Proxy stop no longer reports a rejected
  configuration when the ProxyAgent has no record of it, for example because
  the ProxyAgent ended as above or crashed: the stop completes if the
  ProxyAgent had confirmed it to the network Authority, and otherwise reports
  that global cleanup could not be proven.
- Import a Hysteria2 link's `pinSHA256` certificate pin as the node's
  `certificate_sha256` pin: 64 hex digits in either case, optionally separated
  by `:` or `-` as the official client accepts. The pin replaces CA trust for
  that node but still requires its server name and validity period, and that
  the certificate permit server authentication. The name, the link's `sni` or
  else its server address, must be in the certificate's subjectAltName: Go has
  ignored the Common Name since 1.15, so a certificate made by `openssl req
  -x509 -subj "/CN=…"` without `-addext subjectAltName` fails with "pinned
  certificate does not identify the configured server". The `insecure=1` that
  the official client pairs with a pin is accepted beside it and never stored;
  without a pin it still fails import. An empty, malformed or repeated
  `pinSHA256` fails import; such links previously failed with an
  unsupported-parameter error. The profile stores the existing pin field.
- Accept a Clash node's `skip-cert-verify: true` beside a non-empty
  certificate `fingerprint`, and a sing-box node's `tls.insecure: true` beside
  a certificate or public-key pin. Mihomo, and upstream sing-box for a
  public-key pin, verify such a node against the pin anyway, so the import
  keeps the pin as its only trust anchor, with the same name, validity and
  server-auth checks, and never stores the flag; without a usable pin either
  flag still fails import.
- The local protocol checks now run live Hysteria2, TUIC, AnyTLS, VMess,
  Shadowsocks 2022 and VLESS Reality peers, each of which must refuse a wrong
  credential; the Reality check confirms which key exchange was negotiated.
  The 0.4.0 compatibility assessment listed Hysteria2 and TUIC as locally
  interoperable when only WireGuard had a live peer, and now carries a dated
  correction.

### Security

- Build the network engine with Go 1.27.2 and `golang.org/x/net` v0.60.0.
  They fix the 2026-10-08 Go advisories in HTTP/2, HTTP/1, MIME header and
  TLS ECH handling that the engine's code can reach, and two `html/template`
  advisories in a package it imports without calling the affected code.
- Build with rustls 0.23.46, which fixes the 2026-10-14 rustls advisories
  RUSTSEC-2026-0346, -0347, -0348 and -0349. They concern custom session
  stores, Encrypted Client Hello, Brotli certificate compression and
  post-quantum key exchange, none of which the app's TLS clients use.

### Supply chain

- Build the app, and the release copies of XcodeGen and the Tauri CLI, with
  Xcode 27.1 (27A9275) instead of Xcode 27.0 (27A266a). Release builds accept
  only that exact Xcode.

### Known limitations

- The network Authority stays enrolled to the first installation of the app
  that asked it to start the network on this Mac, and its replay protection
  rejects a start from any other installation. The app of another macOS
  user, or of the same user once the app's engine lineage is gone from that
  user's Keychain, therefore cannot turn System Proxy, Local Proxy or Tunnel
  on, also after the Mac restarts.

## 0.4.0 - Unreleased

- Add Simplified Chinese, Traditional Chinese, English and Japanese with Settings → Appearance → Language, system-language matching, and localized native menus. Language changes preserve the active network session.

### Everyday proxy use and compatibility

- Keep native initialization and settings I/O off the macOS main thread; a slow
  Keychain or file lock no longer blocks window events or quitting. Cancelled
  initialization cannot install a late engine, and window saving uses a single
  background queue without holding the window-event lock during disk writes.
- Load saved preferences independently of the optional macOS Login Item query,
  and preserve newer user changes when that query finishes late.
- Run the local core independently of System Proxy and TUN; keep an explicit full stop.
- Import, update and select profiles while connected, validating candidates and
  restoring the previous runtime after failed replacement or catalog commit.
- Add HTTP/inline providers, rule resources, ordered fallback and session-stable
  balancing, with bounded updates and health checks.
- Add domain-aware DNS policies, encrypted bootstrap and independent node/direct
  resolvers, preserving routing intent, certificate validation and valid negative answers.
- Make port, log level, TUN MTU and explicitly scoped LAN access editable and persistent.
- Support 1024 remote nodes with bounded groups, credentials, paging and probe work.
- Add HTTP/HTTPS CONNECT and distinct certificate/SPKI pins with name/time checks.
- Add configurable global shortcuts and opt-in ordered network rules; manual Stop
  takes precedence over older automatic work.
- Restore action handlers and ordering for newly streamed connection rows; split
  dashboard, import and policy modules for maintainability.

### Network operation and imported policy

- Give SOCKS protocol negotiation its own default handshake budget while
  retaining the TCP socket timeout, explicit setup deadlines and cancellation.
  Slow successful authentication and a failed primary DNS query no longer
  consume the entire setup budget before negotiation or DNS fallback can finish.
- Revalidate the same runtime after a transient read-only status-query failure,
  without restarting the core or interrupting its connections. Identity,
  permission and cleanup failures still require their existing explicit recovery.
- Require the production libbox adapter at compilation so a signed application
  cannot silently omit its real runtime. Failed starts no longer paint active switches.
- Allow System Proxy and TUN independently or together using one engine owner.
- Take over existing system proxy settings on an explicit enable request;
  retain the original settings and restore only fields still owned by CFM.
- Reconcile a restarted background authority after registering the observer
  needed to prove the engine Off. Registration alone no longer claims Off.
- Complete macOS network authorization before starting System Proxy. Keep
  authorization waiting outside runtime deadlines, retain the Agent's own
  authorization reference, and prohibit interactive authorization during writes.
- Treat repeated revocation after quarantine as an unchanged blocked state;
  a late owner disconnect cannot crash the Authority or manufacture Off.
- Preserve supported Clash select groups and ordered process, domain, IP, port,
  network and GEOIP rules; reject unsupported policy instead of dropping it.
- Apply Global/Direct modes to actual routing, and resolve configured process
  matchers with bounded public macOS process/socket queries.
- Show saved nodes and rules while the engine is Off. Store node choices as
  separate profile-envelope preferences without invalidating vault credentials.
  Older envelopes remain byte-compatible when no choices have been saved; a
  rollback to an older binary requires restoring the pre-upgrade profile backup.
  Replacing an imported document starts with that document's default choices.

### Safety and migration

- Retire the privileged helper, external Clash-compatible cores, remote core
  installation, scripts, and PAC execution as runtime paths.
- Replace the old helper with a one-release, non-operational tombstone descriptor that can only
  stop, verify, clean, and unregister legacy state; it can never start a core.
- Keep legacy retirement in an optional maintenance entry. Startup leaves the
  existing VPN and historical data untouched and permits replacement profiles
  to be staged in a separate repository. The destructive retirement transaction
  requires explicit confirmation and native/profile checks only when that
  maintenance operation is selected.
- Start normal System Proxy and TUN requests directly through the existing
  native coordinator, without legacy Prepare or Confirm. Actual legacy runtime
  or service conflicts and unfinished cutover journals still reject the request
  with a visible error. Permission and
  credential checks remain required, and unrelated proxy settings are preserved.
- Add a release-only, signed-Host maintenance transaction that proves global
  Off, unregisters ProxyAgent before GlobalAuthority, preserves the inactive
  one-way legacy tombstone, atomically installs the fixed candidate, and then
  registers GlobalAuthority before ProxyAgent. Append-only recovery events bind
  every step to an unchanged Clash for Windows process and network projection.
  One inode-bound outer lock serializes service and bundle mutations, and
  independent fixed journals cover historical validation migrations and the
  40019→40041 and 40041→40043 GA installations without overwriting earlier
  evidence. The
  canonical allocation ledger prevents a retired validation build or its
  reserved final companion from being reused by a later source closure. The
  validation-only compatibility island can prove the already-installed 40019
  ProxyAgent schema 5 and GlobalAuthority v1.0 Off without weakening the
  current schema 6 / Authority v1.1 runtime path. A lost unregister receipt is
  recovered only after an atomically published, fsynced current-only intent;
  its distinct proof profile records the exact switch from installed-service
  absence to a current Authority v1.1 Off proof and survives interruption after
  the current Authority is registered.
- Retire notarized validation build 40026 and its unbuilt companion 40027 after
  installation admission exposed an ambient Swift/toolchain binding mismatch.
  Tool identity and actual lane execution now share one closed environment:
  the effective account selects a fixed Rust root, Python is exact-version
  pinned, Apple tools come from one validated Developer directory, and the
  Python/Rust/cargo helper/system shell executables are content-bound. New lane
  journals remain isolated until the start/end tool identities agree, and lane
  output is terminated at its fixed streaming bound. Hosted build-40000 CI may
  select only the exact SHA-pinned setup-python executable; production paths
  reject that unsigned-only input. Publication source enumeration uses fixed
  system Git with user/system configuration, unsafe local excludes, fsmonitor,
  and untracked-cache influence removed. Build 40028 and its unbuilt companion
  40029 were then retired before candidate construction because the P0
  source-gate v2 layout could not preserve retries while identifying one
  authoritative success without ambiguity or overwriting failure evidence.
  The corrected append-only source-gate contract initially selected 40030/40031.
  Policy retired 40030 unbuilt. Build 40031 then completed candidate freeze but
  was retired after its private signing attempt failed before canonical signed
  output. Build 40032 then completed candidate freeze and signed five nested
  products in one private attempt, but a split verifier path contract rejected
  the transaction root before Host signing and canonical output. Build 40032
  is also retired. Build 40033 then completed candidate freeze and signed the
  same five nested product roles, but the private helper's process-wide umask
  made `codesign` create non-distributable `0600` resource envelopes. The
  verifier rejected those bytes before Host signing or canonical output, so
  build 40033 is retired as well. Bundle-writing codesign now uses one scoped
  distribution-mode subprocess while the attempt remains private, and a
  signing failure or ambiguous signing output can no longer allocate a fresh
  timestamped signature attempt under the same frozen build. Build 40034 then
  completed candidate freeze and correctly signed the five nested roles plus
  the outer Host, but a post-sign Tombstone verifier omitted the two mandatory
  pre-sign lineage fields from its exact metadata schema. The fail-closed
  verifier rejected the private attempt before canonical output or
  notarization. Build 40034 is retired. One shared validator now re-derives the
  promoted Tombstone manifest from its frozen artifact and manifest, binds it
  to the current source and lockfile, and runs before outer Host signing as
  well as during downstream release verification. Build 40035 then completed
  candidate freeze and entered its single private signing attempt, but the
  attempt terminated during complete private signed-output verification before
  canonical output or notarization. Its durable journal does not identify a
  narrower failing substage, so build 40035 is retired without inferring one.
  Build 40036 then completed freeze, canonical signing, Apple notarization,
  stapling, and Gatekeeper verification. Publication preparation exposed a
  successful-`codesign` stderr contract mismatch and an omitted signed
  GlobalAuthority closure entry. Correcting those tracked release inputs changes
  the frozen product-input identity, so build 40036 is retired before install.
  Build 40037 then completed candidate freeze and one private signing attempt.
  The signing helper returned success and durably wrote a complete
  transformation receipt, but a later mandatory read-only replay failed before
  publish-ready or canonical output. Later replays passed without recovering
  the historical nested cause, and the frozen state machine made the recorded
  failure terminal, so build 40037 is retired before notarization. Future
  signing transactions compile the updater verifier once per operation while
  preserving every independent replay, and may resume only an explicitly
  blocked post-receipt verification of the exact private work without invoking
  the signing helper or receipt creator again.
  Build 40038 then completed candidate freeze and one private signing attempt.
  The helper returned success and produced a validly Developer ID-signed Host
  plus five nested code objects, but a mandatory public-verifier replay failed
  before the transformation receipt was written. Its journal is terminal, so
  build 40038 is retired before canonical output or notarization. New signing
  transactions arm one monotonic retry budget only after exact helper success:
  a typed operational failure closes the poisoned verifier session and replays
  the same public proof once through one fresh source-pinned session. Cleanup,
  startup, semantic, or second operational failure remains terminal; the
  helper, attempt, and receipt creator are never rerun. Build 40039 completed
  freeze and canonical signing, but its original notarization outcome remains
  unknown. Adding SOCKS5 changes the frozen product inputs, so build 40039 is
  retired with all old bytes and receipts preserved and its Apple transaction
  quarantined. Build 40040 then completed freeze and canonical signing, but
  newly published `GO-2026-6354` and `GO-2026-6355` require updating
  `golang.org/x/crypto` to `v0.56.0`. It is retired before notarization with
  its bytes, receipts and source unchanged. The module's minimum Go version
  is now `1.26.0`; Go `1.26.6`, Rust `1.97.1` and all other selected
  dependencies remain unchanged. Build 40041 then completed notarization,
  packaging and the 40019→40041 install, but GA runtime acceptance aborted
  before any mutation: the legacy cutover preflight attributed the live Clash
  for Windows network to the retired installation, while acceptance requires
  that network to be preserved. The preflight now attributes legacy absence to
  the retired installation only, and the install binds its service vocabulary
  to the observed predecessor. Build 40041 is retired after install with its
  bytes, receipts, seals and journals unchanged. Build 40042 was then frozen,
  signed and notarized, but its frozen source's own local lane reproduction
  failed on one release-tooling test that read the lane's ambient toolchain
  selection; that test is now isolated, and 40042 is retired after
  notarization with its bytes and receipts unchanged. Build 40043 then completed
  signing, notarization, packaging and the 40041→40043 install. Authenticated
  profile import exposed a native receipt that encoded the profile UUID in
  uppercase, which the strict Rust consumer rejected and misclassified as vault
  corruption. Receipt encoding and decoding now share the canonical audience
  contract, and vault corruption has a distinct typed error. Build 40043 is
  retired after install before GA runtime collection, with its original bytes,
  seals and journals retained. Build 40044 then completed signing, notarization,
  both package sets and the 40043→40044 installation. Its migration handoff
  child closed after the parent's normal exit because the Darwin process
  identity query misclassified `ESRCH`. Correcting the product code requires
  successor 40045; 40044 retains its original application, package seals,
  receipts and installation journals. No Tunnel confirmation, legacy deletion,
  GA acceptance or publication completed. Build 40045 then completed application
  notarization and the 40044→40045 install. The requested removal of mandatory
  legacy setup from normal startup, together with actual foreign System Proxy
  conflict handling, changes the application and requires successor 40046.
  Build 40045 retains its frozen app, source/legal evidence and installation
  journals without GA acceptance or publication. Build 40046 completed packages
  and installation, then exposed the missing compiled native runtime. The
  runtime and profile-display repairs require build 40047; all 40046 evidence
  remains preserved. Source and CI retries before freeze do not consume builds.
- Let a confirmed fresh installation proceed without an old proxy port that
  never existed. Preparation and recovery recheck that legacy settings,
  managed files, privileged services and network state remain absent. Upgrade
  journals retain their original runtime kind and still require the recorded
  endpoint; missing or unreadable old settings cannot select the fresh path.
- Authenticate nested release-worktree managed caches through bounded,
  descriptor-relative Git administrative control files plus an explicit
  empty-target lifecycle receipt before excluding them from the path/name-only
  secret scan. Stale Git records cannot be replayed by recreating a target
  path. Release-worktree source and generated candidate roots remain scanned,
  aliases into excluded caches fail closed, and candidate or secret bytes are
  never opened.
- Recover an explicitly authorized post-reboot device-number reassignment
  through a separate immutable cache-scope receipt. The original receipt,
  detached source, directory inodes and historical candidates remain unchanged;
  replacement directories, inconsistent remapping and partial records fail
  closed.

### Network architecture

- Add typed engine API, sing-box configuration, application coordinator, and
  Apple-network adapter crates with Off-mediated Proxy/Tunnel switching.
- Add the macOS 15+, arm64 Swift protocol, ProxyAgent, Packet Tunnel System
  Extension, and bounded public `NEPacketTunnelFlow` packet-pump foundation.
- Wire the production Rust `NativeFrameworkBridge`, source-built libbox
  factories in ProxyAgent and Packet Tunnel, and root-context Global Authority
  through exact role-scoped XPC admission. Missing identity, capability,
  ticket, profile, or readiness evidence fails closed; the old helper, a
  downloaded core, private packet-flow APIs, user App Group state, and Data
  Protection Keychain access from the System Extension are not fallbacks.
- Compact the bounded Authority journal before a prepare consumes its
  seven-record finish reserve. Compaction commits a hash-chained checkpoint to
  the next anchored generation, retains only active and previous generations,
  detects rollback, and is fault-tested at every commit and cleanup boundary.

### Configuration and interface

- Replace Clash YAML/REST/WebSocket configuration with a closed app profile
  schema that projects deterministically to native sing-box JSON.
- Add closed typed profile schemas for `direct`, `block`, SOCKS5, Shadowsocks, VMess,
  VLESS/Reality, Trojan, Hysteria2, AnyTLS, and TUIC v5, plus optional
  `route.final`. Persistent profiles contain canonical credential references
  only, including separate TUIC UUID and password references; raw credentials,
  subscriptions/remote resources, scripts, executable paths, and unknown
  fields are rejected. Runtime projection produces empty secret placeholders
  and closed native injection slots. References are immutable: retries must be
  byte-identical and secret rotation requires a new UUID and profile update.
- Add anonymous and authenticated SOCKS5 with IPv4/IPv6/domain endpoints and
  TCP/UDP policy preservation. Import `socks://`/`socks5://` links (plain or
  base64 userinfo), Clash `socks5` nodes, and sing-box SOCKS v5 nodes through one
  adapter. Username and password use separate native vault references and
  RFC 1929 byte bounds. SOCKS4/4a, SOCKS-over-TLS and UDP-over-TCP remain explicit
  unsupported errors; ordinary SOCKS5 does not encrypt transport.
- Unify local file, pasted node link, and remote subscription conversion with
  the same vault-first commit boundary. Add YAML/text file and drag-drop
  admission, strict UTF-8 decoding, and the bounded 512 KiB source limit while
  retaining the independent canonical-profile limit and local reference-only
  manual provisioning. The profile editor still edits only the closed schema.
- Add missing-only credential entry backed by an atomic shared-Keychain vault.
  Renderer and bridge buffers are redacted and zeroized, present references are
  never re-prompted, and explicit two-phase garbage collection deletes only
  revision-bound orphans after repository revalidation.
- Enforce a product-owned TLS 1.2-or-newer policy for enabled proxy TLS,
  authenticated DoH, subscription downloads, and update metadata. Normal
  negotiation prefers TLS 1.3, QUIC requires TLS 1.3, HTTP stays forbidden,
  and no retry-based protocol fallback is used. TUIC 0-RTT is explicitly
  disabled.
- Import restricted upstream sing-box node-list JSON in addition to Clash Meta
  YAML and URI bundles, extracting every inline secret into the Keychain-backed
  vault. Preserve typed VMess/VLESS packet encoding plus HTTP/H2,
  HTTPUpgrade, and V2Ray QUIC transports, including the bounded Mihomo HTTP
  method/path/Host subset; reject unknown semantics and full sing-box
  configurations. Reject V2Ray QUIC without standard enabled TLS and reject
  Vision combined with transport streams or non-XUDP packet framing.
- Make subscription refresh references stable for unchanged documents, rotate
  them only after an explicit immutable-secret conflict, and run exact
  revision-bound orphan cleanup before and after updates. A post-commit cleanup
  failure is returned as an explicit pending state instead of a false rollback.
  Validate the stored profile under the repository lock before any vault write,
  and enforce reference UUID immutability across profile audiences.
- Request `Accept-Encoding: identity`, disable reqwest automatic decompression,
  and reject non-identity response codings while retaining the streamed 512 KiB
  bound.
- Keep Global, Rule, and Direct visible while the engine is Off (disabled),
  preserve the mode switch for valid zero-group snapshots, and display an
  engine-observed Direct fallback as a read-only route rather than a selector.
- Add a private, versioned, digest-bound selected-profile record. Proxy and
  Tunnel starts require that selected profile and fail on missing or stale
  selection instead of silently using DIRECT; Off remains independently
  available.
- Separate DNS roles in both engine modes: two bounded numeric direct resolvers
  are referenced only by remote proxy endpoint `domain_resolver`
  primary/fallback fields. All ordinary DNS and route-level resolution uses one
  of two certificate-verified DoH transports explicitly detoured through the
  selected outbound; Tunnel additionally hijacks packet-flow DNS into that
  path. The pinned source patch permits one bounded retry for transport failure
  or rejected response, never on cancellation; duplicate, loopback,
  link-local, documentation, and virtual-tunnel endpoints are rejected.
- Split the Tauri composition root, platform adapters, and profile repository
  into bounded modules; remove the parallel tracked UI bundle.
- Keep the 0.3.5 dashboard: the same status bar, sidebar, nine pages, liquid-glass
  menus and dialogs, rebuilt against the 0.4.0 command surface instead of being
  replaced. Every entry point whose command is retired is gone with the row,
  button, or menu item around it — Service Mode and the privileged helper,
  starting/stopping and installing cores, the kernel benchmark, the tray-script
  and child-process runners, and the IPv6 switch. Controls the product cannot
  honour are disabled and state the backend's own reason instead of appearing to
  work: LAN exposure, bind address, engine log level, profile mixin, GeoIP
  download, and host DNS restore. Values the 0.4.0 payloads no longer carry are
  reported as unavailable rather than invented, profile mutations are offered
  only while the engine is Off, and an active data plane is claimed only after the
  engine snapshot's runtime identity, generation, digest, and readiness agree.
- Restore the controller-backed read, query, and stream commands (proxy, rule,
  provider, connection, log, DNS, and version surfaces) as a bounded command
  module. Their client is built only from the running engine's app-owned
  loopback controller, never from settings or a profile; the per-run secret is
  redacted out of every returned error, event payload, and `Debug` rendering.
  With no ready engine they fail closed with the unreachable-controller error
  instead of probing an unknown listener.
- Restore the profile-text, subscription, runtime-configuration, engine-switch,
  and shell command surfaces as four bounded command modules. Subscriptions are
  fetched over bounded HTTPS only, validated into the closed profile schema, and
  projected for both modes before they can be stored; the subscription URL lives
  inside the integrity-checked profile envelope and never appears in a profile
  listing. Subscription import converts restricted upstream sing-box
  `outbounds` JSON, Clash Meta YAML `proxies` lists, and node-URI bundles
  (`ss://`, `vmess://`, `vless://` including Reality,
  `trojan://`, `hysteria2://`, `anytls://`, `tuic://`) into that schema at the
  boundary with bounded, alias-rejecting parsers; extracted secrets go to the
  credential vault, never into the stored profile, and import errors identify
  positions and keys instead of echoing document content. Hysteria2/TUIC QUIC
  TLS rejects uTLS and Reality, while AnyTLS retains the standard TLS options.
  The subscription request advertises a
  Clash Meta client so panels serve the modern protocol set. Requests the
  schema cannot honour — unsupported proxy types, disabled certificate
  verification, plugins, chaining, port hopping — fail the import instead of
  being dropped. The runtime-configuration preview redacts the app-owned
  controller secret and fails closed if it survives redaction.
- Express the System Proxy and TUN switches as engine-mode transitions through
  the single Authority-mediated transition path, so neither switch can write a
  system proxy, a DNS server, a route, or a network preference, and neither can
  stop the other mode's data plane. Switches that the projection cannot honour
  (LAN exposure, non-loopback bind address, engine log level, profile mixin) and
  requests to write host DNS or fetch a GeoIP database now fail closed with an
  explicit reason instead of being accepted and ignored. Legacy on-disk Clash
  for Windows profiles are reported, never bulk-converted; their subscriptions
  are re-imported from the live URL instead.
- Restore tray proxy-group switching, window, deep-link, and diagnostics
  helpers. Tray labels and menu ids are bounded and generated, so a controller
  response cannot inject a menu entry, and diagnostics reads
  SystemConfiguration only: the fields the retired `networksetup`, `scutil`, and
  `route` invocations supplied are reported as explicitly unavailable.

### Supply chain and release status

- Move the workspace to GPL-3.0-or-later and pin the arm64 macOS 15 release
  toolchain and source-built libbox inputs.
- Separate the release Mac's Rust SDK from the user's extensible rustup SDK
  with explicit `CFW_RELEASE_RUST_TOOLCHAIN=private`; existing CI retains the
  `global` selection. Both use the same exact five-component v2 surface and
  original digest. SDK preparation occurs before environment consumption,
  with no automatic installation or fallback. Frozen 40043 launchers and
  historical evidence remain unchanged.
- Upgrade the pinned sing-box/libbox source from v1.13.14 to v1.13.15 and
  regenerate all four downstream patches and source digests while retaining
  the upstream DNS-cancellation, UDP-ownership, rule-set descriptor, and
  QUIC/HTTP-upgrade lifecycle fixes.
- Refresh the pinned libbox `golang.org/x/*` closure after `GO-2026-6179` and
  `GO-2026-6180` were reported against `x/mod`. The exact tested closure uses
  `x/mod v0.40.0` with its required `x/crypto`, `x/net`, `x/sync`, `x/sys`,
  `x/term`, `x/text`, and `x/tools` updates; the sealed module cache and
  XCFramework are rebuilt from that closure without a vulnerability ignore.
- Add structured mixed-listener and controller bind-conflict reporting so the
  application can retry only after cleanup and a proven global Off state.
- Build libbox with `with_clash_api`. The patched tree enables the clash API
  whenever a platform log writer is installed and the daemon always installs
  one, so the previous artifact failed every engine start in the stub
  constructor. The pinned tag list is now itself a verified build input: the
  pinned-input gate fails closed when a tag the engine start path requires is
  missing.
- Seal Tauri CLI's complete offline Cargo registry before and after compilation
  while excluding only three validated Cargo runtime tracking/lock files from
  the private snapshot. The exact normalization helper is digest-bound into the
  build-input and final toolchain manifests, and fetch/install warnings block
  the bootstrap.
- Add fail-closed release documentation for nested signing, provisioning,
  notarization, SBOM/license evidence, real packet evidence, weak-network
  recovery, resource limits, and physical-device testing.
- Upgrade physical evidence to aggregate schema v5, receipt schema v3, proof
  schema v3, and trust-policy schema v3. The signed policy digest now binds the
  exact single-machine profile, preventing old receipts from being relabelled
  under the new aggregate marker. The only accepted collector signature
  is PS256 with a source-pinned RSA-PSS-3072 Cloud KMS HSM key version; every
  harness report and receipt binds that identity and the recomputed final
  artifact-hash manifest. Final-candidate schema v3 derives the binding from the
  reopened aggregate and rejects the former caller-only evidence declaration.
  The two fixed clean-OS runs now share one automatically observed physical-
  machine identity, use distinct sealed boot-environment digests, and retain
  independent nonces, receipts, reports, and raw archives. The blocking soak is
  an operator-observed three-hour interval with no reported crash per OS for
  this limited internal distribution; it is not a remote-liveness or public-GA
  endurance claim.
- Build XcodeGen from checksum-bound source with a digest-pinned
  installed-resource patch, isolated resolved-only SwiftPM state, a real project
  generation probe, debug-path stripping, and a complete tree-v2 manifest.
- Replace the generic updater runtime with a project-owned bounded metadata
  check and one-use authorization that revalidates the exact canonical GitHub
  identity before the release page is opened and before a download starts. The
  official DMG release page stays available from About.
- Install a presented release from About when the application runs from
  `/Applications` and is owned by the user. The archive is downloaded within
  fixed bounds and kept only if the complete stream matches the release
  signature for that exact archive; the extracted bundle must be this product,
  the announced version, a strictly newer build and signed by the release
  Developer ID. The core keeps running until Install and Relaunch is chosen.
  The dashboard then stops the core and exits once a separate installer
  process of the same executable holds the installation; that process
  unregisters the `SMAppService` agent and daemon through the existing
  maintenance modes, exchanges the bundles with
  one atomic rename and starts the new application, which registers its own
  services; a start counts only once a new dashboard is still running two
  seconds later. A failure before the exchange leaves the installed
  application as it was, starts it again and is reported on the next launch;
  the reviewed outcome, failures and one bounded line of the extractor's or
  `codesign`'s own output go to the `update.json` diagnostic journal. A
  release whose download failed authentication is not offered again in the
  same run. The release gate `validate_updater_archive.py` applies the same
  archive rules as the installer, including directories their owner can
  fully use and symbolic links that resolve inside the bundle.
- Rotate the updater artifact trust root for 0.4.0 after the 0.3.5 private key
  became unavailable. Existing 0.3.5 installations cannot authenticate the
  new release archive and must install 0.4.0 from its signed, notarized DMG;
  there is no unsigned or alternate-key fallback. The replacement public key
  is embedded in 0.4.0 and its private half remains outside the repository.
- Keep the `SMAppService` maintenance transaction out of the dashboard and
  renderer: only the windowless installer process changes a registration, and
  only after the dashboard that started it has exited. The dashboard itself
  only reads the registration state, through the read-only status mode,
  before it downloads and before it stops the core. Metadata or a browser
  handoff is never reported as installation.
- Release remains blocked until installed-identity proof for shared-Keychain
  provisioning and authenticated in-memory Tunnel injection, physical packet
  capture of the pinned resolver-failover behavior, exact Developer ID and
  provisioning, signed physical-device data-plane and recovery tests, and the
  complete legal/publication evidence set have passed.

## 0.3.5 — 2026-07-21

Updater download progress UI (fixes “stuck on Checking…” after Download & Install).

### Updater
- Separate phases: checking / downloading / installing (no longer misuse Checking for downloads)
- Live percent + progress bar via `cfw://update-progress`
- Ignore `update-available` events while a download is in flight
- Handle “no update available” install result instead of leaving the dialog busy forever


## 0.3.4 — 2026-07-21

Quieter live streams + connections/log Diagnostics fixes (so Check for Update from 0.3.3 can pick this up).

### Diagnostics
- clash-rs `/connections` ports accept **int or string** (stops `invalid type: integer` spam)
- Logs level filter: event delegation + stream-only patch so ALL/INFO/WARNING clicks are not eaten by full re-renders
- Proxy delay **Pending** styled on `cfw-node-card`; in-flight tests keep Pending across snapshot refreshes

### Live streams (WARNING noise)
- Transient controller disconnects (`Connection reset`, `error sending request`, WS protocol reset) reconnect **quietly** — no Diagnostics WARNING spam when TUN flaps `en0`
- Clean WS close / log-level restart no longer logged as errors
- Core `[TUN] default interface changed …` remapped to **INFO** (expected mihomo monitor noise)

### Updater
- Pack `app.tar.gz` with `COPYFILE_DISABLE=1` and reject AppleDouble `._*` entries (fixes `failed to unpack ._Clash for Mac.app`)

## 0.3.3 — 2026-07-21

TUN truthfulness + product About / update feedback + Proxies/profile recovery.

### TUN (fixed)
- Switch reflects **live handoff** (`tun.enable` + managed root core), not a stale disk flag
- Fresh launch defaults to **Off** unless Service Mode actually owns a TUN-capable core
- Service Mode always spawns **mihomo** for TUN (clash-rs controller-ready ≠ working utun)
- Handoff readiness uses **controller API + netstat** — unprivileged `lsof` cannot see root listeners
- Failed handoff scrub `cache.db` (root-owned) and wait for ports before restarting in-process core
- Helper `serve` processes an existing control session **immediately** (no 5s first-wait race)
- After TUN up: sync persisted **Rule/Global** mode; auto-escape **Global+DIRECT** blackhole (looked like “TUN broken”)
- Heartbeat 10s / stale 90s to reduce helper tearing down a live TUN session
- System Proxy toggles **never** mutate `tun_mode`; UI re-syncs TUN after proxy changes

### Proxies / Profiles
- Entering Proxies, TUN toggle, settings-changed, and profile switch all **re-fetch controller snapshot**
- Empty mode chrome hidden when controller has no groups; clearer empty copy
- Removed meaningless Profiles hover 4-icon bar (use card click + right-click menu)
- Profile switch rollback re-applies previous profile; `controller_snapshot` no longer fails wholly when connections lag
- `set_proxy_mode` persists `runtime_mode`; hot-reload failures are no longer silent success

### About / Check for Update
- App menu **About Clash for Mac** and **Check for Update…** open the native product card

## 0.3.2 — 2026-07-21

Update UX + measured clash-rs vs mihomo answers on Apple Silicon.

### Updates
- macOS app menu: **Check for Update…** under About Clash for Mac
- Startup silent check; General header shows **→ vX.Y.Z** when a newer release exists
- Confirm → download/install via `tauri-plugin-updater` (GitHub `latest.json`)

### Measured kernel compare (not docs-only)
- `scripts/kernel_compare.py` runs clash-rs and mihomo on high localhost ports
- Ships `resources/benchmarks/kernel-compare-latest.json` with cold-start, controller API, delay, and weak-timeout burst metrics
- General **Core Bench** row + Feedback panel show the measured speedup / reliability deltas
- This host’s run: **~1.27×** faster cold start & controller API vs mihomo; weak-net / delay success tied at 100% — **not** a CFW 「3×」 claim

## 0.3.1 — 2026-07-21

Apple Silicon–only hardening with a Rust core default. Version stays **0.3.1**.

### What is stronger than CFW / prior builds (verifiable)
- **Default core: clash-rs (Rust)** on arm64; mihomo kept only as automatic fallback
- **Tauri 2 native shell** (not Electron) — smaller process model than CFW’s Electron
- **Apple Silicon only** — no Intel / Universal Binary tax
- Typed sysproxy / DNS / Login Item / helper paths from earlier 0.2–0.3 work remain

### Explicit product decisions (not unfinished “todos”)
- **UI:** Tauri + WebKit (`ui/`) is the product UI. React is **not** stronger than Tauri and is **not** a migration target.
- **TUN:** SMAppService privileged helper is the **production** path. Network Extension is research-only, not shipped.
- **App Sandbox:** **Rejected** for the main app while root helper TUN is required (Sandbox and root helper conflict).
- **「3× CFW」:** Not advertised. Perf CI records metrics only (`claim_3x_cfw: false`) until a same-machine CFW baseline exists.

### Platform
- Docs/CI refuse `x86_64` / lipo (`scripts/assert_apple_silicon.sh`)
- Sparkle remains cancelled (`tauri-plugin-updater` since 0.2.0)

### Core
- `CoreKind` default = `clash_rs`
- Pinned clash-rs **v0.10.7** aarch64 (checksum-verified)
- `--compatibility` is opt-in via `CFW_CLASH_RS_COMPAT` (avoids first-boot GeoIP stall)
- Mihomo fallback on missing binary / start / controller readiness failure

## 0.3.0 — 2026-07-21

Delay-test correctness + TUN stability for Apple Silicon.

### Proxies / delay test
- Failed and timed-out probes show **Timeout** (no more **N/A**)
- After one full round, every tested node has a final state (no leftover **Pending**)
- Adaptive concurrency (`hardwareConcurrency`, clamped 4–16; drops to 2 when backgrounded)
- Visible nodes probed first; incremental delay label patching (no full-page flash per chunk)
- Cancel on group switch / leave Proxies / second click
- Network default-route changes mark delay badges stale

### TUN
- Launch reconcile: if `tun_mode` + Service Mode Enabled → full root handoff (not a half start)
- TUN owns core → config changes force helper respawn (hot reload skipped for utun/routes)
- Safer defaults: `stack: mixed`, `strict-route: true`, DNS hijack `any:53` + `[::]:53`
- TUN settings Save always re-applies runtime config when TUN is on

### Stack
- Continues 0.2.0 platform path (SCPreferences proxy/DNS, Login Item, updater)

### Not included in 0.3.0 (do not treat as shipped)
- Network Extension / App Sandbox / React UI migration
- mihomo rewrite or clash-rs default cutover *(cutover landed in 0.3.1)*
- Proven 「3× CFW」 CI gates
- Universal Binary (permanently rejected; Apple Silicon only)
- Sparkle (superseded by tauri-plugin-updater)

## 0.2.0 — 2026-07-21

Apple Silicon performance and platform hardening release (P0–P2).

### P0
- ControllerClient process-wide singleton / reqwest connection pool reuse
- cfw-helper control-session supervision is FSEvents/`notify` event-driven (5s heartbeat fallback; no fixed 500ms poll)

### P1
- Connections page incremental DOM patching (no full-page `innerHTML` on every WS tick)
- Silent Start uses `ActivationPolicy::Accessory` + Dock hide; tray Show restores Regular + Dock
- Start at Login uses `SMAppService::mainAppService` Login Item (migrates off user LaunchAgent)

### P2
- DNS set/restore via SCPreferences with `networksetup` fallback
- `tauri-plugin-updater` + GitHub Releases `latest.json` (arm64)

### Stack (carried from Unreleased)
- Rust **1.97.1**; YAML via noyalib `compat-serde-yaml`; reqwest **0.13**; Tauri **2.11.5**
- System Proxy SCPreferences path; UI `ui/src/` + esbuild

## 0.1.0 — 2026-07-20

### Beta release candidate

- Apple Silicon–only Clash for Mac (Tauri 2) rebuild of CFW 0.20.39 core daily path
- Bundled mihomo core provisioning + CoreManager start/stop
- Profiles: remote URL import, local/text import, drag-drop, update scheduler, apply, edit, QR
- Proxies / Providers / Rules / Connections / Logs wired to live controller (no offline fake rows)
- System Proxy with network-service snapshot restore + editable bypass list
- Service Mode via SMAppService + privileged helper for TUN (requires Developer ID + Login Items approval)
- Tray menu + `clash://` deep links; optional tray latency tooltip
- Default `profile.store-selected`; Logs Copy + Open Folder
- Developer ID signed, notarized, and stapled (DMG + app)
- Release gate documented in `RELEASE.md`
