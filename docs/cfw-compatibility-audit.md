# CFW compatibility audit — 2026-09-08

The comparison baseline is the installed macOS CFW 0.20.39 application and CFM
0.4.0 build 40046. CFW features below were inspected in its installed UI and
packaged renderer, not inferred from the number of CFM sidebar pages. Local
source changes are separate from the installed build.

The reported startup failures occurred with CFW closed. Observing CFW running
later does not explain those failures. The existing-proxy rejection is a
separate behavior and must not be presented as their root cause.

## Blocking runtime defects

The native Xcode target linked the Objective-C adapter archive but did not
publish an importable `CFWLibboxObjC` module. Consequently,
`canImport(Libbox) && canImport(CFWLibboxObjC)` excluded the service runtime,
and the factory used its `libboxUnavailable` branch. Configuration checking
could still pass because it requires only `Libbox`. Swift package tests also
did not exercise that excluded service implementation.

Requiring the adapter at compilation reproduced the missing-module error in
the existing Xcode project. Publishing the module exposed three additional
errors in the previously excluded code: an optional result incompatible with
the Objective-C throwing protocol, mutable local state captured by a concurrent
callback, and a nullable Go conflict result imported as nonoptional by Swift.
The source correction publishes the module, requires it in the native target,
fixes the return type, uses a synchronized first-path flag, and handles the
nullable result at the Objective-C boundary.

An isolated executable using build 40046's libbox and the real profile structure
then started and stopped the production System Proxy runtime successfully.
It used a private runtime directory and did not apply system proxy settings,
read actual credentials, or establish remote proxy traffic. This is runtime
component evidence, not signed installed-app or replacement-network acceptance.

The General page also used desired mode to paint switches green, including
failed starts. The source correction uses verified activity for green switches
and retains separate retry/cancel controls. Existing-system-proxy conflicts now
have a specific, secret-free error across the native/Rust boundary. Other
coarsely classified startup errors still need more useful diagnostic categories.

## Installed 40047 follow-up and 40048 corrections

The installed 40047 application now displays the actual PROXY selector with
three members and all 12 supported source rules. Offline selection changes
persist, and the complete profile uses the existing vault credentials. A real
production-runtime test through the selected remote node returned Google 204
and OpenAI 401 responses. System Proxy and TUN acceptance remain separate.

An explicit System Proxy start still failed at the existing-proxy gate. Build
40048 accepts existing valid settings, snapshots them before takeover, compares
the snapshot under the preferences lock, and retains conditional restoration.
It also removes the service-registration cycle: a restarted Authority can
register without claiming Off, then the registered ProxyAgent supplies the
observations needed for normal reconciliation. An active lease still rejects
the operation. Neither change waives a real networking failure.

## Installed 40048 follow-up and 40049 corrections

40048 completed installation and service recovery. A System Proxy test with
CFW processes absent still failed: macOS authorization blocked the running
Agent, the start RPC expired, and a delayed disconnect crashed the Authority
after cleanup had entered quarantine. No OS proxy activation was observed.

40049 requests authorization before the engine coordinator starts a generation
or begins restoring an existing System Proxy session, including application
shutdown. The user interaction has a separate five-minute bound and acquires
no additional runtime/Authority lease; an existing connection remains running
while the user responds. Runtime heartbeats and stop barriers retain their
existing deadlines.
The Agent keeps its authorization reference and makes later rights checks
noninteractive. Read-only recovery remains possible without a new write grant.
Repeated revocation leaves quarantine intact until genuine cleanup is proven.

This follows the public Authorization Services distinction between requesting
rights and checking them without interaction; releasing one reference does not
revoke shared authorizations used by other processes.
[Apple authorization flags](https://developer.apple.com/documentation/security/authorizationflags)
describe the interaction and shared-right revocation options.

The local network authorization rule delegates to
`authenticate-admin-nonshared` with a 30-second credential timeout. Retaining an
AuthorizationRef does not make that grant permanent. A later stop or switch can
therefore require macOS authorization again. Restoration authorization is
skipped when no ownership journal exists, so TUN-only operation does not acquire
an unrelated network-preferences grant. Unattended cleanup after credentials
expire remains an explicit recovery failure, not a successful Off state.

## Functionality comparison

### Corrections prepared for build 40047

The table below preserves the installed 40046 baseline. The successor source
now implements independent System Proxy/TUN switches (including both enabled
under one Packet Tunnel owner), selector groups, supported ordered Clash rules,
country rule sets, real Direct/Global routing and saved policy views while Off.
Node choices are separate envelope preferences, so changing a choice does not
change the imported document's Keychain audience. Configuration replacements
use the new source defaults; the original profile backup supports binary rollback.

Production-runtime tests with the pinned libbox have exercised real HTTP
forwarding, process-name rejection, mode changes, selector changes and controller
group/rule data. Normal-user process matching uses bounded public `libproc`
queries limited to configured names/paths; it requires no additional privilege.
These component checks still do not prove installed SystemConfiguration or TUN
behavior. Installation and OS readback must complete before that claim.

Automatic url-test/fallback groups, providers, arbitrary source DNS settings,
LAN exposure and a standalone core while both switches are Off remain gaps.
Unsupported policy imports fail explicitly before profile commit.

| Capability | Installed CFW UI/code | CFM 40046 baseline | Assessment |
| --- | --- | --- | --- |
| Core without system proxy or TUN | Core and local mixed listener can remain available independently | `Off` stops the engine; starts select System Proxy or Tunnel | Major missing use case |
| System Proxy and TUN together | Independent controls; both are shown enabled in the inspected CFW view | Exclusive `Off / SystemProxy / Tunnel` engine enum and owner transitions | Deliberate product regression, not an OS requirement |
| Usable native startup | Working CFW connection is observed | Reported CFM starts fail; native implementation was excluded from compilation | Release blocker; source repair is not yet installed |
| Configuration import | Retains the YAML document, groups and rules | Converts Clash `proxies` only | Major compatibility loss |
| Routing groups | Configured groups and choices; group editor | Imported groups disappear; a simple selector may be synthesized | Original group behavior and default selection are not preserved |
| Routing rules / GEOIP | YAML rules, rule editor and GeoIP database | Profile schema accepts only `route.final`; legacy GeoIP file is displayed but not consumed | A Rules page does not restore the missing rule model |
| Proxy/rule providers | Provider controls in the proxy view | Provider management explicitly unsupported | Sidebar entry is not implemented parity |
| DNS configuration | Nameservers, fallback, fake-IP filter, nameserver policy and DNS IPv6 | App-owned resolver projection; source DNS and hosts are not imported | Major configuration loss |
| TUN configuration | Stack, interface, auto-detection, DNS hijack and routing options | Fixed Packet Tunnel projection and network plan | Native integration replaces the mechanism but omits user controls |
| Local port / bind address | Editable port and bind; optional randomized ports | Bounded internal port selection, fixed loopback bind | Useful customization removed |
| Allow LAN | User-controlled | Always unavailable | Restriction needs an explicit exposure policy, not a parity claim |
| Log level | Editable | Pinned to info | Restriction also impedes diagnosis |
| IPv6 | Visible controls | Internal setting; no equivalent user preference | Missing control |
| Online profile changes | Runtime profile switching, update and merge/diff flows | Profile mutations require engine Off | Workflow regression |
| Import display metadata | Separate profile index retains display name | Individual YAML import uses its filename; source type was omitted from list IPC | Source-label repair committed separately; automatic CFW index import absent |
| Subscription metadata | Update interval, request headers, update-through-proxy and quota-related handling | Basic import/update and stored source URL; no equivalent complete preference set | Partial |
| Mixin / parsers / scripts | User-facing YAML/JavaScript customization | Removed or unavailable | Intentional execution-boundary restriction, with substantial capability loss |
| Delay tests | Configurable target, timeout and ordering | Fixed HTTPS target; basic probes exist | Partial |
| Connection policies | None/chain/all and profile/mode-change policies | Basic close actions and a session-only break option | Partial; process-owner adapter is unsupported |
| Logs / connections / traffic | Core-backed live views | Real controller commands exist, but unavailable when engine cannot run | Current failures prevent runtime acceptance; not independent completed features |
| Offline Proxies view | Configuration/core model remains accessible separately from OS proxy switches | Controller-only view becomes unavailable when Off or failed | Missing offline configuration view |
| Persistence | Extensive preferences | Six persisted UI fields; several view switches are session-only | Significant preference loss |
| Tray / shortcuts / automation | Group styles, delay indicator, custom icons, enhanced tray, configurable shortcuts, SSID strategies | Basic tray/navigation and fixed shortcuts; no equivalent full configuration | Partial or absent |

Windows-only UWP, TAP and Wintun controls are not counted as missing macOS
features. Scripts and arbitrary executable/core replacement should not be
restored by removing input or signature checks; their scope requires a clear
extension model.

## Improvements supported by evidence

- The installed CFM executable is arm64; the installed CFW executable is x86_64.
  This proves native architecture, not a measured performance advantage.
- `du -sk` measured 93,580 KiB for CFM and 273,740 KiB for CFW (approximately
  91.4 MiB versus 267.3 MiB of installed disk usage). These are not RAM, startup
  time, energy, or compressed-download measurements.
- Imported credentials use reference-only profile data and a Keychain vault.
  Provisioning, missing-value detection, rotation and cleanup have typed tests.
  CFW's source YAML carries inline credential values. The additional storage
  boundary is a concrete improvement; it does not compensate for broken starts.
- SystemExtension/NetworkExtension and SMAppService provide an Apple-native
  lifecycle. The ProxyAgent runs as the user; a privileged Global Authority
  remains. It is incorrect to describe the whole product as unprivileged.
- The source supports modern outbound shapes including Hysteria2, TUIC v5,
  AnyTLS and VLESS/Reality. This is a protocol capability, not proof that all of
  them work in the installed 40046 application.
- Ownership-aware restoration, bounded IPC, stale-generation rejection, secret
  redaction and signed update verification are meaningful protections. Blanket
  restrictions on ordinary settings are not automatically security improvements.

There is no current evidence for better reliability, throughput, latency, DNS
behavior, battery life or overall usability than CFW.

## Recommended product contract

Keep one controlled engine owner, but model core availability, local listeners,
system proxy settings and TUN interception separately. Enabling TUN should not
require removing a working local proxy listener. Enabling system proxy should
refer to that listener, with explicit conflict handling and restoration.

Restore a typed group/rule/DNS configuration model and retain import semantics
before claiming CFW migration. Show configuration data separately from live
controller state, so users can inspect and prepare profiles while the engine
is Off. Restore ordinary settings with bounded validation; treat scripting and
network exposure as explicit capabilities.

Release acceptance must exercise the installed application actually starting
its compiled runtime, applying/restoring the requested networking, and sending
real traffic with CFW closed. Tests of configuration parsing or an unavailable
runtime branch cannot substitute for this.
