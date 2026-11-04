// The diagnostics dialogs: the projected configuration, the network services
// and a DNS query through the running engine.
import { state } from "./state.js";
import { escapeHtml, errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { captureEngineIdentityToken, controllerActionAllowed, engineIdentityTokenIsCurrent } from "./engine-identity.js";
import { networkDiagnosticsView, serviceProxyLabel } from "./network-diagnostics.js";

export function createDiagnosticsDialogs({ renderPage, renderGlassOverlays, runtimeProjectionActionAllowed }) {
  function renderConfigPreview(dialog) {
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="${escapeHtml(t("Projected configuration preview"))}">
          <h3>${escapeHtml(t("Projected configuration"))}</h3>
          <p class="glass-dialog-copy">${escapeHtml(t("The selected profile projected for the current mode. The app-owned controller secret is redacted."))}</p>
          <pre class="glass-code">${escapeHtml(dialog.payload ?? "")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button>
            <button type="button" class="glass-btn" data-glass-copy-text>${escapeHtml(t("Copy"))}</button>
          </div>
        </div>
      `);
  }

  function renderNetworkServices(dialog) {
    const presentation = networkDiagnosticsView(dialog.payload, serviceProxyLabel);
    const rows = presentation.rows.map((row) => `<tr>${row.map((cell) => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`).join("");
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="${escapeHtml(presentation.title)}">
          <h3>${escapeHtml(presentation.title)}</h3>
          <p class="glass-dialog-copy">${escapeHtml(presentation.description)}</p>
          ${dialog.payload.platform === "windows" ? `<p class="glass-dialog-copy">${escapeHtml(presentation.summary[0][0])}: ${escapeHtml(presentation.summary[0][1])}</p>` : ""}
          <div class="glass-table-wrap"><table class="glass-table"><thead><tr>${presentation.columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("")}</tr></thead><tbody>${rows || `<tr><td colspan="3">${escapeHtml(presentation.empty)}</td></tr>`}</tbody></table></div>
          ${presentation.unavailable.length ? `<p class="glass-dialog-copy">${escapeHtml(t("Unavailable fields"))}: ${escapeHtml(presentation.unavailable.join(", "))}</p>` : ""}
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button></div>
        </div>
      `);
  }

  function renderDnsQuery(dialog) {
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="${escapeHtml(t("DNS query"))}">
          <h3>${escapeHtml(t("Resolve through the running engine"))}</h3>
          <label>${escapeHtml(t("Name"))}<input data-glass-dns-name value="${escapeHtml(dialog.payload?.name ?? "www.gstatic.com")}" /></label>
          <label>${escapeHtml(t("Type"))}<input data-glass-dns-type value="${escapeHtml(dialog.payload?.type ?? "A")}" /></label>
          <pre class="glass-code">${escapeHtml(dialog.payload?.result ?? t("Enter a name and Query."))}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button>
            <button type="button" class="glass-btn" data-glass-dns-confirm>${escapeHtml(t("Query"))}</button>
          </div>
        </div>
      `);
  }

  function render(dialog) {
    switch (dialog.kind) {
      case "preview-config": return renderConfigPreview(dialog);
      case "network-services": return renderNetworkServices(dialog);
      case "dns-query": return renderDnsQuery(dialog);
      default: throw new TypeError(`diagnostics dialog ${dialog.kind} is unknown`);
    }
  }

  function bind() {
    document.querySelectorAll("[data-glass-dns-confirm]").forEach((button) => {
      button.addEventListener("click", async () => {
        const name = document.querySelector("[data-glass-dns-name]")?.value?.trim() ?? "";
        const type = document.querySelector("[data-glass-dns-type]")?.value?.trim() || "A";
        if (!controllerActionAllowed(t("DNS query"), "dns")) {
          state.glassDialog = { kind: "dns-query", payload: { name, type, result: t("Engine is Off; start the engine before querying DNS.") } };
          renderGlassOverlays();
          return;
        }
        const token = captureEngineIdentityToken();
        try {
          const result = await invoke("dns_query", { name, record_type: type, recordType: type });
          if (!engineIdentityTokenIsCurrent(token)) return;
          state.glassDialog = { kind: "dns-query", payload: { name, type, result: JSON.stringify(result, null, 2) } };
          renderGlassOverlays();
        } catch (error) {
          if (!engineIdentityTokenIsCurrent(token)) return;
          const message = errorText(error);
          appendLog("error", "dns", t("DNS query failed: {message}", { message: message }));
          state.glassDialog = { kind: "dns-query", payload: { name, type, result: message } };
          renderGlassOverlays();
        }
      });
    });
  }

  const actions = {
    "show-network-interfaces": async () => {
      try {
        const diagnostics = await invoke("network_diagnostics");
        networkDiagnosticsView(diagnostics, serviceProxyLabel);
        state.networkDiagnostics = diagnostics;
        state.glassDialog = {
          kind: "network-services",
          payload: diagnostics,
        };
        renderGlassOverlays();
        return;
      } catch (error) {
        appendLog("error", "network", errorText(error));
      }
      renderPage();
    },
    "preview-runtime-config": async () => {
      if (!runtimeProjectionActionAllowed(t("Configuration preview"))) return;
      try {
        const body = await invoke("read_runtime_config_text");
        state.glassDialog = { kind: "preview-config", payload: body };
        renderGlassOverlays();
        return;
      } catch (error) {
        appendLog("error", "engine", t("Configuration preview failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
    "dns-query": async () => {
      state.glassDialog = { kind: "dns-query", payload: { name: "www.gstatic.com", type: "A", result: "" } };
      renderGlassOverlays();
    },
  };

  return { dialogs: { kinds: ["preview-config", "network-services", "dns-query"], render, bind }, actions };
}
