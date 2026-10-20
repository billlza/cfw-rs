import { t } from "./i18n.js";

const ADAPTER_TYPES = Object.freeze({ 6: "Ethernet", 24: "Loopback", 71: "Wi-Fi", 131: "Tunnel" });
const ADAPTER_STATES = Object.freeze({ 1: "Up", 2: "Down", 3: "Testing", 4: "Unknown", 5: "Dormant", 6: "Not present", 7: "Lower layer down" });

// One presentation for the settings rows and network details dialog. Adapter
// state and user-wide proxy options are separate Windows observations.
export function networkDiagnosticsView(diagnostics, serviceProxyLabel) {
  if (diagnostics?.platform === "windows") {
    const { adapters, user_proxy: proxy } = diagnostics;
    const keys = ["manual_proxy_enabled", "auto_config_enabled", "auto_detect_enabled"];
    if (!Array.isArray(adapters) || adapters.length > 128 || !proxy
      || keys.some((key) => typeof proxy[key] !== "boolean")
      || adapters.some((row) => !Number.isInteger(row.index) || row.index <= 0
        || typeof row.display_name !== "string" || !row.display_name
        || !Number.isInteger(row.interface_type) || !Number.isInteger(row.operational_status))
      || new Set(adapters.map((row) => row.index)).size !== adapters.length) {
      throw new TypeError("Windows network diagnostics are invalid");
    }
    const description = t("Adapter status and current-user proxy settings are reported separately.");
    const proxyLabel = [proxy.manual_proxy_enabled ? t("Manual proxy") : null,
      proxy.auto_config_enabled ? "PAC" : null, proxy.auto_detect_enabled ? "WPAD" : null]
      .filter(Boolean).join(", ") || t("Off");
    const rows = adapters.map((row) => [row.display_name,
      Object.hasOwn(ADAPTER_TYPES, row.interface_type) ? t(ADAPTER_TYPES[row.interface_type]) : t("Type {value}", { value: row.interface_type }),
      Object.hasOwn(ADAPTER_STATES, row.operational_status) ? t(ADAPTER_STATES[row.operational_status]) : t("Unknown ({value})", { value: row.operational_status })]);
    return {
      title: t("Network adapters"), description,
      columns: [t("Adapter"), t("Type"), t("Status")], rows, unavailable: [], empty: t("No network adapters"),
      summary: [
        [t("Current user proxy"), proxyLabel, t("LAN proxy options; this does not report VPN-specific proxies, effective PAC results or ownership.")],
        [t("Network adapters"), t("{count} adapter(s)", { count: adapters.length }), t("Adapter status does not prove Internet connectivity.")],
        ...rows.map(([name, kind, status]) => [name, status, kind]),
      ],
    };
  }
  if (!diagnostics || diagnostics.platform !== undefined) throw new TypeError("Network diagnostics platform is invalid");
  const services = diagnostics.services ?? [];
  const proxied = diagnostics.proxied_services ?? [];
  return {
    title: t("Network services"),
    description: t("Read from SystemConfiguration only. The default-route interface, hardware port and BSD device are not reported: the child-process tools that supplied them are gone."),
    columns: [t("Service"), t("Order"), t("Proxy")],
    empty: t("No services"),
    rows: services.map((service) => [service.display_name ?? service.service_id ?? t("unknown"),
      String(service.order ?? "—"), serviceProxyLabel(service)]),
    unavailable: diagnostics.unavailable ?? [],
    summary: [
      [t("Service order"), services.length ? t("{count} service(s)", { count: services.length }) : "none",
        t("Read from SystemConfiguration only; no child process is spawned.")],
      [t("Services carrying a proxy"), proxied.length ? proxied.join(", ") : "none",
        t("Any service with a proxy setting enabled, whoever owns it. Ownership is not reported.")],
      ...services.map((service) => [service.display_name ?? service.service_id ?? t("unknown"),
        serviceProxyLabel(service), t("set order {value1}", { value1: service.order ?? "-" })]),
    ],
  };
}
