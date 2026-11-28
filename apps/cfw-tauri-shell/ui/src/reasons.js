import { state } from "./state.js";
import { t } from "./i18n.js";
import { platformPresentation } from "./platform-presentation.js";
import { savedSettingsHeldFor } from "./runtime-settings.js";

/// Reasons the dashboard shows next to a control the 0.4.0 backend refuses.
/// Each one states what the product does instead, so a disabled switch is never
/// unexplained and never silently does nothing.
export const REASONS = Object.freeze({
  get allowLan() { return t("LAN sharing uses a separate listener restricted to explicitly trusted private source networks."); },
  get bindAddress() { return t("The local proxy and controller stay on loopback. LAN devices use their own listener address and port."); },
  get logLevel() { return t("Changes apply through a validated runtime replacement and are saved for the next launch."); },
  get mixin() { return t("Mixin is unavailable: the engine configuration is projected by the app, and an imported document may only describe routing and outbound policy."); },
  get geoip() { return t("Country rules use sing-box rule sets, downloaded on first start and refreshed daily while the engine runs. An existing Clash Country.mmdb file is not used."); },
  get mainlandChinaDirect() { return t("In Rule mode, traffic that no profile rule matches goes direct when it is bound for mainland China, and the app's own DNS answers mainland names through encrypted DNS in mainland China. The first start with each profile downloads the China rule sets through the proxy and waits for them; they then refresh daily while the core runs. It does not apply to a profile that routes directly. Existing connections may reconnect when this changes."); },
  get dnsLeakProtection() { return t("In TUN Mode, every connection to port 853 is refused, so DNS over TLS or DNS over QUIC that an app or a system setting carries itself cannot pass names around the core's DNS: it falls back to plain DNS, which TUN Mode always hands to the core. The core resolves through the app's encrypted DNS over the selected route, or through the profile's own DNS policy when it declares one; with Mainland China direct on, mainland names use encrypted DNS in mainland China, dialled directly. DNS over HTTPS shares port 443 and is not covered. It does nothing in System Proxy mode, where the app never changes the system DNS."); },
  get webrtcLeakProtection() { return t("In TUN Mode, STUN is refused, so a web page cannot ask a STUN server which address this computer's traffic comes from: neither the real address, through a server that is routed directly, nor the proxy's exit, through a proxied one. It holds in Rule and Global mode and leaves Direct mode alone. Calls and other peer-to-peer connections that rely on STUN go through a relay instead, or fail. It does not hide an address the browser reads from this computer's own network interfaces, which a page can see once it has camera or microphone permission. It does nothing in System Proxy mode, where a browser's WebRTC traffic never passes through the app."); },
  get tcpConcurrency() { return t("When a server name has several addresses, the core connects to them at once and keeps the first connection that opens, instead of trying one address after another. It applies in every mode to the connections the core opens itself, such as those to a proxy server named by a domain and to a destination that goes direct. IPv4 and IPv6 still start one after the other, and at most eight addresses of a family are dialled at a time. Connections carried through a proxy and UDP are not changed. Existing connections may reconnect when this changes."); },
  get restoreDns() { return t(platformPresentation(state.payload.product.operating_system).systemDns); },
  get engineNotOff() { return t("Stop the core before credential maintenance or legacy migration."); },
});

/// Whether a switch of the runtime network settings shows a value that was
/// read, in the dashboard state asked about. Before the first read and after
/// a failed one, which keeps the previous snapshot beside its error, the
/// value is not known and the switch is drawn off.
export function networkSettingsKnown(dashboard) {
  return dashboard.runtimeSettings != null && dashboard.runtimeSettingsError == null;
}

/// Why those settings cannot be changed at this moment, or null. Every
/// control of them shows it and stays disabled meanwhile. What leaves the
/// values unknown is said first, a failed read before settings that were not
/// read yet: the reason then stands beside a switch that is off whatever the
/// setting is. In a migration's own window the migration owns the network and
/// holds known values too, which their switches still show. Settings that
/// are saved but not the ones the engine runs with are held as well, and
/// their switches show what it runs with: a change of one of them is written
/// with the rest of the saved ones, and would apply each of those unasked.
/// Where no change of them can be made at all, as while a legacy cleanup is
/// pending, that is said in place of the advice to apply them.
///
/// The window that starts a migration is not held. It closes once the
/// migration's window is ready, and holding it takes more than this reason:
/// an action already under way and the native switches would have to follow.
export function networkSettingsReason(dashboard) {
  if (!networkSettingsKnown(dashboard)) return dashboard.runtimeSettingsError ?? t("Network settings are loading");
  if (dashboard.migrationHandoff) return t("Finish migration before changing network settings");
  return dashboard.runtimeSettings.in_force ? null : savedSettingsHeldFor(dashboard.runtimeSettings);
}
