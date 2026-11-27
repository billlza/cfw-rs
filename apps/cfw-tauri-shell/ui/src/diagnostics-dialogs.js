// The diagnostics dialogs: the projected configuration, the network services
// and a DNS query through the running engine.
import { state } from "./state.js";
import { escapeHtml, errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { captureEngineIdentityToken, controllerActionAllowed, engineIdentityTokenIsCurrent } from "./engine-identity.js";
import { networkDiagnosticsView, serviceProxyLabel } from "./network-diagnostics.js";
import { askForDialog } from "./dialog-requests.js";
import { readNetworkDiagnostics } from "./system-info.js";

export function createDiagnosticsDialogs({ renderPage, renderGlassOverlays, runtimeProjectionActionAllowed }) {
  // A read draws again only a page that shows what it came to: Settings the
  // network settings that were observed or could not be read, and Logs the
  // line a failure adds. Another page shows nothing of it and is not drawn
  // again: it holds what the user entered there and has not saved, a profile
  // in its editor for one.
  const settingsShown = () => state.activePage === "settings";
  const logsShown = () => state.activePage === "logs";

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
    const query = state.glassDialog;
    if (query?.kind !== "dns-query") return;
    // What is typed in the query is kept in it: the page draws the dialog
    // again from its state, as every render of the page does while it is open.
    for (const [selector, key] of [["[data-glass-dns-name]", "name"], ["[data-glass-dns-type]", "type"]]) {
      document.querySelectorAll(selector).forEach((field) => {
        field.addEventListener("input", () => { query.payload[key] = field.value; });
      });
    }
    // Its answer is shown in it while it is open, where it keeps its place.
    // Once it was closed, or another dialog took its place, the answer opens
    // nothing: it would open the query again over what the user opened since.
    const answer = (name, type, result) => {
      if (state.glassDialog !== query) return;
      query.payload = { name, type, result };
      renderGlassOverlays();
    };
    document.querySelectorAll("[data-glass-dns-confirm]").forEach((button) => {
      button.addEventListener("click", async () => {
        const name = document.querySelector("[data-glass-dns-name]")?.value?.trim() ?? "";
        const type = document.querySelector("[data-glass-dns-type]")?.value?.trim() || "A";
        if (!controllerActionAllowed(t("DNS query"), "dns")) {
          answer(name, type, t("Engine is Off; start the engine before querying DNS."));
          return;
        }
        const token = captureEngineIdentityToken();
        try {
          const result = await invoke("dns_query", { name, record_type: type, recordType: type });
          if (!engineIdentityTokenIsCurrent(token)) return;
          answer(name, type, JSON.stringify(result, null, 2));
        } catch (error) {
          if (!engineIdentityTokenIsCurrent(token)) return;
          const message = errorText(error);
          appendLog("error", "dns", t("DNS query failed: {message}", { message: message }));
          answer(name, type, message);
        }
      });
    });
  }

  // These two read before they open, so each is asked for at the press and
  // opens only while it is the dialog that was asked for last.
  const actions = {
    "show-network-interfaces": async () => {
      const latest = askForDialog(state);
      let opened = false;
      try {
        const diagnostics = await readNetworkDiagnostics();
        if (latest()) {
          state.glassDialog = {
            kind: "network-services",
            payload: diagnostics,
          };
          opened = true;
        }
      } catch (error) {
        appendLog("error", "network", errorText(error));
        if (settingsShown() || logsShown()) renderPage();
        return;
      }
      // Settings shows what was observed, whoever asked for it.
      if (settingsShown()) renderPage();
      else if (opened) renderGlassOverlays();
    },
    "preview-runtime-config": async () => {
      if (!runtimeProjectionActionAllowed(t("Configuration preview"))) return;
      const latest = askForDialog(state);
      try {
        const body = await invoke("read_runtime_config_text");
        if (!latest()) return;
        state.glassDialog = { kind: "preview-config", payload: body };
        renderGlassOverlays();
        return;
      } catch (error) {
        appendLog("error", "engine", t("Configuration preview failed: {error}", { error: errorText(error) }));
        if (logsShown()) renderPage();
      }
    },
    "dns-query": async () => {
      state.glassDialog = { kind: "dns-query", payload: { name: "www.gstatic.com", type: "A", result: "" } };
      renderGlassOverlays();
    },
  };

  return { dialogs: { kinds: ["preview-config", "network-services", "dns-query"], render, bind }, actions };
}
