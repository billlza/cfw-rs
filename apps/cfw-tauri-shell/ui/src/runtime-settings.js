import { escapeHtml, errorText } from "./format.js";

export const RUNTIME_LOG_LEVELS = Object.freeze(["trace", "debug", "info", "warn", "error", "fatal", "silent"]);

function integer(text, minimum, maximum, label) {
  const value = String(text).trim();
  if (!/^\d+$/u.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${label} must be ${minimum}–${maximum}`);
  }
  return Number(value);
}

export function runtimeDraft(settings) {
  return {
    port: settings.preferred_mixed_port === null ? "" : String(settings.preferred_mixed_port),
    level: settings.log_level,
    mtu: String(settings.tunnel_mtu),
    ipv6DNS: settings.ipv6_dns_enabled ?? true,
    allow: settings.allow_lan,
    lanAddress: settings.lan_proxy?.listen ?? "0.0.0.0",
    lanPort: String(settings.lan_proxy?.port ?? 7898),
    lanSources: settings.lan_proxy?.allowed_source_cidrs.join("\n") ?? "",
  };
}

export function preferencesFromRuntimeDraft(draft) {
  if (!RUNTIME_LOG_LEVELS.includes(draft.level)) throw new Error("Choose a supported log level");
  if (typeof draft.ipv6DNS !== "boolean") throw new Error("Choose whether to request IPv6 DNS answers");
  const sources = draft.lanSources.split(/[\n,]/u).map((value) => value.trim()).filter(Boolean);
  if (draft.allow && !sources.length) throw new Error("Enter the trusted LAN source ranges before enabling sharing");
  const lan = sources.length ? {
    listen: draft.lanAddress.trim(),
    port: integer(draft.lanPort, 1024, 65535, "LAN port"),
    allowed_source_cidrs: sources,
  } : null;
  if (lan && (!/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(lan.listen) || sources.length > 32)) {
    throw new Error("Enter an IPv4 listener and at most 32 trusted source ranges");
  }
  const preferred = String(draft.port).trim() ? integer(draft.port, 1024, 65535, "Proxy port") : null;
  if (lan && lan.port === preferred) throw new Error("The local and LAN proxy ports must be different");
  return {
    preferred_mixed_port: preferred,
    log_level: draft.level,
    tunnel_mtu: integer(draft.mtu, 1280, 9000, "TUN MTU"),
    ...(draft.ipv6DNS ? {} : { ipv6_dns_enabled: false }),
    allow_lan: draft.allow === true,
    lan_proxy: lan,
  };
}

export function createRuntimeSettingsUI({ state, invoke, appendLog, renderPage, refreshRuntime, dismissOtherDialogs }) {
  let request = 0;
  function accept(snapshot) {
    if (!snapshot || typeof snapshot.settings !== "object" || typeof snapshot.effective !== "object"
      || !RUNTIME_LOG_LEVELS.includes(snapshot.settings.log_level)
      || typeof snapshot.settings.allow_lan !== "boolean"
      || (snapshot.settings.ipv6_dns_enabled !== undefined && typeof snapshot.settings.ipv6_dns_enabled !== "boolean")
      || typeof snapshot.effective.ipv6_dns_enabled !== "boolean"
      || !(snapshot.revision === null || typeof snapshot.revision === "string")) {
      throw new TypeError("Runtime settings response is invalid");
    }
    state.runtimeSettings = snapshot;
    state.runtimeSettingsError = null;
    state.toggles.allowLan = snapshot.settings.allow_lan;
    state.logLevel = snapshot.effective.log_level;
  }
  async function load() {
    const captured = ++request;
    try {
      const snapshot = await invoke("read_runtime_settings_snapshot");
      if (captured !== request) return false;
      accept(snapshot);
      return true;
    } catch (error) {
      if (captured === request) state.runtimeSettingsError = errorText(error);
      return false;
    }
  }
  async function open(enableLAN = false) {
    if (state.engineMutationBusy || state.migrationHandoff) return;
    if (!await load()) { renderPage(); return; }
    dismissOtherDialogs();
    const draft = runtimeDraft(state.runtimeSettings.settings);
    if (enableLAN) draft.allow = true;
    state.runtimeSettingsDialog = { draft, revision: state.runtimeSettings.revision, saving: false, error: null };
    renderPage();
  }
  function close() {
    if (state.runtimeSettingsDialog?.saving) return;
    state.runtimeSettingsDialog = null;
  }
  async function save(settings, revision, dialog = null) {
    if (state.engineMutationBusy || state.migrationHandoff) throw new Error("Another network operation is in progress");
    state.engineMutationBusy = true;
    if (dialog) { dialog.saving = true; dialog.error = null; }
    renderPage();
    let saved = false;
    try {
      const snapshot = await invoke("write_runtime_settings_snapshot", { settings, revision });
      ++request;
      accept(snapshot);
      saved = true;
      if (state.runtimeSettingsDialog === dialog) state.runtimeSettingsDialog = null;
      appendLog("info", "settings", "Runtime settings applied and saved");
    } catch (error) {
      if (dialog) dialog.error = errorText(error);
      appendLog("error", "settings", `Runtime settings were not applied: ${errorText(error)}`);
      await load();
    } finally {
      // A failed candidate may have restored the old core under a new identity.
      // Refresh that state on both outcomes instead of predicting a rollback.
      try { await refreshRuntime(); } catch (error) {
        appendLog("error", "settings", `Could not refresh runtime status: ${errorText(error)}`);
      }
      state.engineMutationBusy = false;
      if (dialog) dialog.saving = false;
      renderPage();
    }
    return saved;
  }
  async function toggleLAN(enabled) {
    if (enabled) { await open(true); return false; }
    if (!await load()) throw new Error(state.runtimeSettingsError);
    return save({ ...state.runtimeSettings.settings, allow_lan: false }, state.runtimeSettings.revision);
  }
  function renderDialog() {
    const dialog = state.runtimeSettingsDialog;
    if (!dialog) return "";
    const d = dialog.draft;
    const disabled = dialog.saving ? " disabled" : "";
    return `<div class="glass-dialog-backdrop" data-runtime-dismiss></div>
      <section class="glass-dialog runtime-settings-dialog" role="dialog" aria-modal="true" aria-labelledby="runtime-settings-title">
        <h2 id="runtime-settings-title">Network settings</h2>
        <p class="glass-dialog-copy">Changes apply to the current core. Existing connections may reconnect.</p>
        <label class="glass-input-label">Local proxy port <input class="glass-input" data-runtime-field="port" inputmode="numeric" placeholder="Automatic" value="${escapeHtml(d.port)}"${disabled}></label>
        <label class="glass-input-label">Log level <select class="glass-input" data-runtime-field="level"${disabled}>${RUNTIME_LOG_LEVELS.map((level) => `<option value="${level}"${d.level === level ? " selected" : ""}>${level}</option>`).join("")}</select></label>
        <label class="glass-input-label">TUN MTU <input class="glass-input" data-runtime-field="mtu" inputmode="numeric" value="${escapeHtml(d.mtu)}"${disabled}></label>
        <label class="glass-input-label"><input type="checkbox" data-runtime-field="ipv6DNS"${d.ipv6DNS ? " checked" : ""}${disabled}> Request IPv6 DNS answers</label>
        <p class="glass-dialog-copy">Turn off for a proxy server with a broken IPv6 exit. TUN still captures IPv6 traffic.</p>
        <label class="glass-input-label"><input type="checkbox" data-runtime-field="allow"${d.allow ? " checked" : ""}${disabled}> Share with trusted LAN devices</label>
        <p class="glass-dialog-copy">LAN devices use a separate port. Enter the private source networks allowed to use it.</p>
        <label class="glass-input-label">LAN listener <input class="glass-input" data-runtime-field="lanAddress" value="${escapeHtml(d.lanAddress)}"${disabled}></label>
        <label class="glass-input-label">LAN port <input class="glass-input" data-runtime-field="lanPort" inputmode="numeric" value="${escapeHtml(d.lanPort)}"${disabled}></label>
        <label class="glass-input-label">Trusted source ranges <textarea class="glass-textarea" data-runtime-field="lanSources" rows="3" placeholder="192.168.1.0/24"${disabled}>${escapeHtml(d.lanSources)}</textarea></label>
        ${dialog.error ? `<p class="glass-dialog-copy warning" role="alert">${escapeHtml(dialog.error)}</p>` : ""}
        <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-runtime-dismiss${disabled}>Cancel</button><button type="button" class="glass-btn primary" data-runtime-save${disabled}>${dialog.saving ? "Applying…" : "Apply"}</button></div>
      </section>`;
  }
  function bindDialog() {
    document.querySelectorAll("[data-runtime-field]").forEach((input) => input.addEventListener("input", () => {
      const dialog = state.runtimeSettingsDialog;
      const key = input.dataset.runtimeField;
      if (!dialog || dialog.saving || !Object.hasOwn(dialog.draft, key)) return;
      dialog.draft[key] = key === "allow" || key === "ipv6DNS" ? input.checked : input.value;
    }));
    document.querySelectorAll("[data-runtime-dismiss]").forEach((button) => button.addEventListener("click", () => { close(); renderPage(); }));
    document.querySelectorAll("[data-runtime-save]").forEach((button) => button.addEventListener("click", async () => {
      const dialog = state.runtimeSettingsDialog;
      if (!dialog || dialog.saving) return;
      try { await save(preferencesFromRuntimeDraft(dialog.draft), dialog.revision, dialog); }
      catch (error) { dialog.error = errorText(error); renderPage(); }
    }));
  }
  function bindPage() {
    document.querySelectorAll("[data-runtime-log-level]").forEach((input) => input.addEventListener("change", async () => {
      const level = input.value;
      if (!RUNTIME_LOG_LEVELS.includes(level)) return;
      try {
        if (!await load()) throw new Error(state.runtimeSettingsError);
        await save({ ...state.runtimeSettings.settings, log_level: level }, state.runtimeSettings.revision);
      } catch (error) { appendLog("error", "settings", errorText(error)); renderPage(); }
    }));
  }
  return { load, open, close, save, toggleLAN, renderDialog, bindDialog, bindPage };
}
