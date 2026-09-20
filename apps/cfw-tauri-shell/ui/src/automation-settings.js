import { t } from "./i18n.js";
import { escapeHtml, errorText } from "./format.js";

export const SHORTCUT_ACTIONS = Object.freeze([
  ["show_dashboard", "Show dashboard"], ["toggle_core", "Start / stop core"],
  ["toggle_system_proxy", "Toggle System Proxy"], ["toggle_tunnel", "Toggle TUN"],
]);
const MODES = [["off", "Stop core"], ["local_proxy", "Local proxy"], ["system_proxy", "System Proxy"], ["tunnel", "TUN"], ["tunnel_system_proxy", "TUN + System Proxy"]];

export function automationDraft(settings) {
  return { shortcuts: Object.fromEntries(settings.shortcuts.map(({ action, shortcut }) => [action, shortcut])),
    enabled: settings.network_enabled, rules: structuredClone(settings.network_rules) };
}
export function preferencesFromAutomationDraft(draft) {
  const shortcuts = SHORTCUT_ACTIONS.flatMap(([action]) => {
    const shortcut = (draft.shortcuts[action] ?? "").trim();
    return shortcut ? [{ action, shortcut }] : [];
  });
  if (draft.enabled && !draft.rules.length) throw new Error(t("Add a network rule before enabling automatic changes"));
  const network_rules = draft.rules.map((rule) => {
    if (!MODES.some(([mode]) => mode === rule.mode)) throw new Error(t("Choose a supported network mode"));
    if (!["wifi", "wired", "ssid"].includes(rule.network.type)) throw new Error(t("Choose a supported network match"));
    if (rule.network.type === "ssid" && (!rule.network.name || new TextEncoder().encode(rule.network.name).length > 32)) {
      throw new Error(t("Enter a Wi-Fi name containing 1–32 UTF-8 bytes"));
    }
    return { mode: rule.mode, network: rule.network.type === "ssid" ? { type: "ssid", name: rule.network.name } : { type: rule.network.type } };
  });
  return { shortcuts, network_enabled: draft.enabled, network_rules };
}

export function createAutomationSettingsUI({ state, invoke, renderPage, appendLog, dismissOtherDialogs }) {
  let opening = 0;
  async function open() {
    if (state.migrationHandoff) return;
    const epoch = ++opening;
    const snapshot = await invoke("read_automation_settings");
    if (epoch !== opening) return;
    dismissOtherDialogs();
    state.automationDialog = { snapshot, draft: automationDraft(snapshot.settings), saving: false, error: null };
    renderPage();
  }
  function close() { if (state.automationDialog?.saving) return; ++opening; state.automationDialog = null; }
  async function save() {
    const dialog = state.automationDialog;
    if (!dialog || dialog.saving) return;
    try {
      const settings = preferencesFromAutomationDraft(dialog.draft);
      dialog.saving = true; dialog.error = null; renderPage();
      await invoke("write_automation_settings", { settings, revision: dialog.snapshot.revision });
      state.automationDialog = null;
      appendLog("info", "settings", t("Global shortcuts and network rules saved"));
    } catch (error) {
      dialog.error = errorText(error);
      appendLog("error", "settings", t("Automation settings were not applied: {error}", { error: dialog.error }));
    } finally { dialog.saving = false; renderPage(); }
  }
  function renderDialog() {
    const dialog = state.automationDialog;
    if (!dialog) return "";
    const { draft, snapshot, saving } = dialog;
    const disabled = saving ? " disabled" : "";
    const network = snapshot.network;
    const networkLabel = snapshot.network_error ?? (network ? `${network.kind === "wifi" ? "Wi-Fi" : t("Wired")} · ${network.interface}${network.ssid ? ` · ${network.ssid}` : ""}` : t("No active physical network"));
    return `<div class="glass-dialog-backdrop" data-automation-dismiss></div>
      <section class="glass-dialog automation-settings-dialog" role="dialog" aria-modal="true" aria-labelledby="automation-title">
        <h2 id="automation-title">${escapeHtml(t("Shortcuts & network rules"))}</h2>
        <p class="glass-dialog-copy">${escapeHtml(t("Global shortcuts work while this app is in the background. Include Command, Option or Control; leave a field empty to disable it."))}</p>
        ${SHORTCUT_ACTIONS.map(([action, label]) => `<label class="glass-input-label">${label}<input class="glass-input" data-shortcut-action="${action}" value="${escapeHtml(draft.shortcuts[action] ?? "")}" placeholder="${escapeHtml(t("Command+Option+P"))}"${disabled}></label>`).join("")}
        <label class="glass-input-label"><input type="checkbox" data-network-enabled${draft.enabled ? " checked" : ""}${disabled}> ${escapeHtml(t("Apply network rules automatically"))}</label>
        <p class="glass-dialog-copy">${escapeHtml(t("The first matching rule applies after a network change or when enabled. Manual Stop stays stopped on the same network. Rules run while CFM is open."))}</p>
        <p class="glass-dialog-copy">${escapeHtml(t("Current network: {network}", { network: networkLabel }))}</p>
        ${network?.kind === "wifi" && !network.ssid ? `<p class="glass-dialog-copy">${escapeHtml(t("macOS is not providing the Wi-Fi name. Rules for a named Wi-Fi network cannot match until the name is available."))}</p><button type="button" class="glass-btn ghost" data-wifi-permission${disabled}>${escapeHtml(t("Allow Wi-Fi name access…"))}</button>` : ""}
        <button type="button" class="glass-btn ghost" data-network-refresh${disabled}>${escapeHtml(t("Refresh network status"))}</button>
        ${dialog.notice ? `<p class="glass-dialog-copy" role="status">${escapeHtml(dialog.notice)}</p>` : ""}
        <div class="automation-rule-list">${draft.rules.map((rule, index) => `<div class="automation-rule-row">
          <select aria-label="${escapeHtml(t("Network match {number}", { number: index + 1 }))}" data-network-match="${index}"${disabled}>${[["wifi", t("Any Wi-Fi")], ["ssid", t("Named Wi-Fi")], ["wired", t("Wired")]].map(([value, label]) => `<option value="${value}"${rule.network.type === value ? " selected" : ""}>${escapeHtml(t(label))}</option>`).join("")}</select>
          ${rule.network.type === "ssid" ? `<input class="glass-input" aria-label="${escapeHtml(t("Wi-Fi name {number}", { number: index + 1 }))}" data-network-name="${index}" value="${escapeHtml(rule.network.name ?? "")}" placeholder="${escapeHtml(t("Exact Wi-Fi name"))}"${disabled}>` : ""}
          <select aria-label="${escapeHtml(t("Network action {number}", { number: index + 1 }))}" data-network-mode="${index}"${disabled}>${MODES.map(([value, label]) => `<option value="${value}"${rule.mode === value ? " selected" : ""}>${escapeHtml(t(label))}</option>`).join("")}</select>
          <button type="button" data-network-up="${index}" aria-label="${escapeHtml(t("Move rule {number} up", { number: index + 1 }))}"${saving || index === 0 ? " disabled" : ""}>↑</button>
          <button type="button" data-network-remove="${index}" aria-label="${escapeHtml(t("Remove rule {number}", { number: index + 1 }))}"${disabled}>${escapeHtml(t("Remove"))}</button>
        </div>`).join("")}</div>
        <button type="button" class="glass-btn ghost" data-network-add${saving || draft.rules.length >= 16 ? " disabled" : ""}>${escapeHtml(t("Add network rule"))}</button>
        ${dialog.error ?? snapshot.error ? `<p class="glass-dialog-copy warning" role="alert">${escapeHtml(dialog.error ?? snapshot.error)}</p>` : ""}
        <div class="glass-dialog-actions"><button class="glass-btn ghost" data-automation-dismiss${disabled}>${escapeHtml(t("Cancel"))}</button><button class="glass-btn primary" data-automation-save${disabled}>${saving ? t("Applying…") : t("Apply")}</button></div>
      </section>`;
  }
  function bindDialog() {
    const dialog = state.automationDialog;
    if (!dialog) return;
    const bind = (selector, event, handler) => document.querySelectorAll(selector).forEach((el) => el.addEventListener(event, () => { if (!dialog.saving && state.automationDialog === dialog) handler(el); }));
    bind("[data-shortcut-action]", "input", (el) => { dialog.draft.shortcuts[el.dataset.shortcutAction] = el.value; });
    bind("[data-network-enabled]", "change", (el) => { dialog.draft.enabled = el.checked; });
    bind("[data-network-match]", "change", (el) => { dialog.draft.rules[Number(el.dataset.networkMatch)].network = { type: el.value, ...(el.value === "ssid" ? { name: "" } : {}) }; renderPage(); });
    bind("[data-network-name]", "input", (el) => { dialog.draft.rules[Number(el.dataset.networkName)].network.name = el.value; });
    bind("[data-network-mode]", "change", (el) => { dialog.draft.rules[Number(el.dataset.networkMode)].mode = el.value; });
    bind("[data-network-add]", "click", () => { dialog.draft.rules.push({ network: { type: "wifi" }, mode: "system_proxy" }); renderPage(); });
    bind("[data-network-remove]", "click", (el) => { dialog.draft.rules.splice(Number(el.dataset.networkRemove), 1); renderPage(); });
    bind("[data-network-up]", "click", (el) => { const i = Number(el.dataset.networkUp); if (i > 0) [dialog.draft.rules[i - 1], dialog.draft.rules[i]] = [dialog.draft.rules[i], dialog.draft.rules[i - 1]]; renderPage(); });
    bind("[data-wifi-permission]", "click", async () => {
      try { await invoke("request_wifi_name_access"); dialog.notice = t("Respond to the macOS permission prompt, then refresh network status."); }
      catch (error) { dialog.error = errorText(error); }
      renderPage();
    });
    bind("[data-network-refresh]", "click", async () => {
      try { const fresh = await invoke("read_automation_settings"); dialog.snapshot.network = fresh.network; dialog.snapshot.network_error = fresh.network_error; dialog.notice = null; }
      catch (error) { dialog.error = errorText(error); }
      renderPage();
    });
    bind("[data-automation-save]", "click", save);
    bind("[data-automation-dismiss]", "click", () => { close(); renderPage(); });
  }
  return { open, close, renderDialog, bindDialog, save };
}
