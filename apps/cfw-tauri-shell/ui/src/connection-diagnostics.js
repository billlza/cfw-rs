import { t, formatDate } from "./i18n.js";
import { escapeHtml } from "./text-format.js";
import { probeWebRtc } from "./connection-webrtc.js";
import { diagnosticFailure, httpVerdict, udpComparison } from "./connection-diagnostics-model.js";

export function createConnectionDiagnostics({ state, runtime, invoke, renderPage, webRtc = probeWebRtc, requestId = () => crypto.randomUUID() }) {
  const model = { active: null, hidden: true, report: null, dns: null, udp: null, information: null, error: null, binding: null };
  const binding = () => JSON.stringify([runtime.engineIdentityEpoch, state.engine, state.proxyGroups?.map((group) => [group.name, group.now])]);
  const stale = () => model.binding !== null && model.binding !== binding();
  const ip = (value) => model.hidden ? t("Hidden") : value;
  const html = (value) => escapeHtml(String(value));

  async function run(kind, address) {
    if (model.active) return;
    const captured = binding();
    if (stale() || kind === "connectivity") {
      model.report = null; model.dns = null; model.udp = null; model.information = null;
    }
    if (kind === "information") model.information = null;
    if (kind === "dns") model.dns = null;
    if (kind === "udp") model.udp = null;
    model.binding = captured;
    model.error = null;
    const id = requestId();
    const abort = new AbortController();
    const active = { id, kind, abort };
    model.active = active;
    renderPage();
    try {
      let value;
      if (kind === "udp") value = await webRtc({ signal: abort.signal });
      else if (kind === "connectivity") value = await invoke("connection_diagnostics", { requestId: id });
      else if (kind === "dns") value = await invoke("connection_dns_check", { requestId: id });
      else if (kind === "information") value = await invoke("connection_ip_information", { requestId: id, ip: address });
      else throw new TypeError("unknown diagnostic kind");
      if (abort.signal.aborted) throw new Error("cancelled");
      if (binding() !== captured) throw new Error("runtime_changed");
      model[{ connectivity: "report", dns: "dns", udp: "udp", information: "information" }[kind]] = value;
    } catch (error) {
      model.error = diagnosticFailure(typeof error === "string" ? error : error?.message);
    } finally {
      if (model.active === active) model.active = null;
      renderPage();
    }
  }

  function observed(item, format) {
    if (!item) return `<span class="diagnostic-muted">${html(t("Not checked"))}</span>`;
    return item.status === "observed" ? format(item.value) : `<span class="diagnostic-attention">${html(diagnosticFailure(item.reason))}</span>`;
  }

  function egress(label, item) {
    return `<div class="diagnostic-egress"><span>${html(label)}</span>${observed(item, (value) => `<strong>${html(ip(value.ip))}</strong><small>${html([value.country, value.colo].filter(Boolean).join(" · "))}</small>`)}</div>`;
  }

  function renderServices() {
    const services = model.report?.services;
    if (!services) return "";
    return `<section class="diagnostic-section"><h2>${html(t("Service connectivity"))}</h2><p>${html(t("HTTP responses do not verify login, subscription access, or regional eligibility."))}</p>
      <div class="diagnostic-services">${services.map((service) => `<div class="diagnostic-service"><div><b>${html(service.name)}</b><small>${html(service.host)}</small></div>
        ${observed(service.response, (value) => { const verdict = httpVerdict(value.http_status); return `<div><span class="diagnostic-${verdict.tone}">${html(verdict.label)}</span><small>HTTP ${html(value.http_status)} · ${html(value.elapsed_ms)} ms</small></div>`; })}
        <div>${service.egress ? observed(service.egress, (value) => `<span>${html(ip(value.ip))}</span><small>${html(value.country || t("Unknown"))}</small>`) : `<span class="diagnostic-muted">${html(t("Exit IP not supplied"))}</span>`}</div></div>`).join("")}</div></section>`;
  }

  function lookupAddresses() {
    if (!model.report || stale()) return [];
    return [
      [t("CFM request path"), model.report.routed_egress],
      ...model.report.services.filter((service) => service.egress).map((service) => [service.name, service.egress]),
    ].filter(([, item]) => item.status === "observed").map(([label, item]) => ({ label, ip: item.value.ip }));
  }

  function renderInformation() {
    const info = model.information;
    const facts = (rows) => `<dl class="diagnostic-facts">${rows.map(([label, value]) => `<div><dt>${html(label)}</dt><dd>${html(value || t("Not supplied"))}</dd></div>`).join("")}</dl>`;
    const classification = (value) => value === true ? t("Marked by source") : value === false ? t("Not marked by source") : t("Not supplied");
    return `<section class="diagnostic-section"><h2>${html(t("IP information"))}</h2><p>${html(t("Optional lookup sends the selected IP to IPQuery for approximate location, ASN and network classifications."))}</p>
      <div class="diagnostic-actions">${lookupAddresses().map((value, index) => `<button data-diagnostic-ip="${index}" ${model.active ? "disabled" : ""}>${html(t("Look up {name}", { name: value.label }))}</button>`).join("")}</div>
      ${info ? `${facts([["IP", ip(info.ip)], [t("Region"), [info.country, info.region, info.city].filter(Boolean).join(" · ")], ["ASN", info.asn], [t("Operator"), info.company], ["ISP", info.isp], [t("Time zone"), info.timezone]])}
        <h3>${html(t("Network classifications"))}</h3>
        ${facts([[t("IPQuery risk score"), String(info.risk.risk_score)], ["VPN", classification(info.risk.is_vpn)], [t("Proxy"), classification(info.risk.is_proxy)], ["Tor", classification(info.risk.is_tor)], [t("Hosting network"), classification(info.risk.is_datacenter)], [t("Mobile network"), classification(info.risk.is_mobile)]])}
        <p>${html(t("The source's weighted score ranges from 0 to 150. It is not a risk probability or an official Claude score. A missing classification does not prove safety."))}</p>
        <p class="diagnostic-muted">${html(t("Residential status, abuse history and account eligibility are not assessed."))}</p>
        <small>${html(t("Source: IPQuery · data and attribution: ipquery.io/sources"))}</small>` : ""}</section>`;
  }

  function renderDns() {
    return `<section class="diagnostic-section"><div class="diagnostic-section-head"><h2>${html(t("DNS resolver check"))}</h2><button data-action="diagnostic-dns" ${model.active ? "disabled" : ""}>${html(t("Check DNS"))}</button></div>
      <p>${html(t("Sends four random system DNS queries to bash.ws and shows the resolvers it observes. This does not establish DNS encryption or prove the absence of leaks."))}</p>
      ${model.dns ? `<dl class="diagnostic-facts">${model.dns.resolvers.map((resolver) => `<div><dt>${html(ip(resolver.ip))}</dt><dd>${html([resolver.country, resolver.asn].filter(Boolean).join(" · ") || t("Not supplied"))}</dd></div>`).join("")}</dl><small>${html(t("{count} of 4 system lookups failed or timed out.", { count: model.dns.lookup_failures }))}</small>` : ""}</section>`;
  }

  function renderUdp() {
    const value = model.udp;
    const comparison = value?.status === "observed" ? udpComparison(value.addresses, model.report) : null;
    const messages = { matched: t("Observed UDP and HTTPS exits match."), different: t("Different UDP and HTTPS exits observed. Review your routing and TUN settings."), unconfirmed: t("No comparable HTTPS result; run connectivity checks first.") };
    return `<section class="diagnostic-section"><div class="diagnostic-section-head"><h2>WebRTC / UDP</h2><button data-action="diagnostic-udp" ${model.active ? "disabled" : ""}>${html(t("Check UDP"))}</button></div>
      <p>${html(t("Uses Cloudflare STUN to observe this window's UDP path. No camera or microphone. Other browsers may behave differently."))}</p>
      ${value ? (value.status === "observed" ? `<strong>${html(value.addresses.map(ip).join(" · "))}</strong><p class="diagnostic-${comparison === "different" ? "attention" : "neutral"}">${html(messages[comparison])}</p>` : `<p class="diagnostic-attention">${html(value.status === "unsupported" ? t("WebRTC is unavailable in this window") : diagnosticFailure(value.reason))}</p>`) : ""}</section>`;
  }

  function render() {
    const report = model.report;
    const route = report?.route.kind === "engine_proxy" ? t("Through the running CFM proxy") : report?.route.kind === "tunnel" ? t("System sockets under the active TUN") : t("System sockets; no explicit proxy");
    return `<div class="connection-diagnostics" data-diagnostics-root aria-busy="${Boolean(model.active)}">
      <div class="diagnostic-heading"><div><h1>${html(t("Connection diagnostics"))}</h1><p>${html(t("Check exit addresses and connectivity on demand."))}</p></div><div class="diagnostic-actions">
        <button data-action="diagnostic-hide">${html(t(model.hidden ? "Show IP addresses" : "Hide IP addresses"))}</button>
        ${model.active ? `<button data-action="diagnostic-cancel">${html(t("Cancel"))}</button>` : `<button class="primary" data-action="diagnostic-run">${html(t("Run checks"))}</button>`}</div></div>
      <p class="diagnostic-scope">${html(t("Checks contact Cloudflare, ipify, Claude, ChatGPT and Anthropic. Results stay in this window; nothing runs automatically."))}</p>
      ${model.active ? `<p role="status" class="diagnostic-progress">${html(t("Checking…"))}</p>` : ""}
      ${model.error ? `<p role="alert" class="diagnostic-attention">${html(model.error)}</p>` : ""}
      ${stale() ? `<p role="status" class="diagnostic-attention">${html(t("These results predate a network change. Run the checks again."))}</p>` : ""}
      ${report ? `<small>${html(route)} · ${html(formatDate(new Date(report.observed_at_ms), { hour: "2-digit", minute: "2-digit", second: "2-digit" }))}</small>` : ""}
      <div class="diagnostic-egresses">${egress(t("System request path"), report?.system_egress)}${egress(t("CFM request path"), report?.routed_egress)}</div>
      <p class="diagnostic-muted">${html(t("System sockets can still traverse a VPN or TUN. Different destination rules may use different exits."))}</p>
      <div class="diagnostic-families">${["ipv4", "ipv6"].map((family) => `<div><b>${family === "ipv4" ? "IPv4" : "IPv6"}</b>${observed(report?.[family], (value) => `<span>${html(ip(value))}</span>`)}</div>`).join("")}</div>
      ${renderServices()}${renderInformation()}${renderDns()}${renderUdp()}
    </div>`;
  }

  const actions = {
    "diagnostic-run": () => run("connectivity"),
    "diagnostic-dns": () => run("dns"),
    "diagnostic-udp": () => run("udp"),
    "diagnostic-hide": () => { model.hidden = !model.hidden; renderPage(); },
    "diagnostic-cancel": async () => {
      const active = model.active;
      if (!active) return;
      active.abort.abort();
      if (active.kind !== "udp") {
        try { await invoke("cancel_connection_diagnostics", { requestId: active.id }); }
        catch (error) { model.error = diagnosticFailure(typeof error === "string" ? error : error?.message); renderPage(); }
      }
    },
  };
  function bindPage() {
    document.querySelectorAll("[data-diagnostic-ip]").forEach((button) => button.addEventListener("click", () => {
      const address = lookupAddresses()[Number(button.dataset.diagnosticIp)];
      if (address) return run("information", address.ip);
    }));
  }
  return { render, actions, bindPage };
}
