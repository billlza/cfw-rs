import { state } from "./state.js";
import { t } from "./i18n.js";
import { platformPresentation } from "./platform-presentation.js";

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
  get restoreDns() { return t(platformPresentation(state.payload.product.operating_system).systemDns); },
  get engineNotOff() { return t("Stop the core before credential maintenance or legacy migration."); },
});
