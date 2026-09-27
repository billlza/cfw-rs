import { t } from "./i18n.js";
import { escapeHtml, errorText } from "./format.js";
import { runtimeDialogFrame } from "./native-runtime-settings.js";

export const RUNTIME_LOG_LEVELS = Object.freeze(["trace", "debug", "info", "warn", "error", "fatal", "silent"]);

function integer(text, minimum, maximum, label) {
  const value = String(text).trim();
  if (!/^\d+$/u.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(t("{label} must be {minimum}–{maximum}", { label: label, minimum: minimum, maximum: maximum }));
  }
  return Number(value);
}

export function runtimeDraft(settings, effective = null) {
  const ipv6DNS = settings.ipv6_dns_enabled ?? effective?.ipv6_dns_enabled ?? true;
  return {
    port: settings.preferred_mixed_port === null ? "" : String(settings.preferred_mixed_port),
    level: settings.log_level,
    mtu: String(settings.tunnel_mtu),
    ipv6DNS,
    initialIPv6DNS: ipv6DNS,
    ipv6DNSInherited: settings.ipv6_dns_enabled === undefined,
    allow: settings.allow_lan,
    lanAddress: settings.lan_proxy?.listen ?? "0.0.0.0",
    lanPort: String(settings.lan_proxy?.port ?? 7898),
    lanSources: settings.lan_proxy?.allowed_source_cidrs.join("\n") ?? "",
  };
}

export function preferencesFromRuntimeDraft(draft) {
  if (!RUNTIME_LOG_LEVELS.includes(draft.level)) throw new Error(t("Choose a supported log level"));
  if (typeof draft.ipv6DNS !== "boolean") throw new Error(t("Choose whether to enable IPv6 DNS"));
  const sources = draft.lanSources.split(/[\n,]/u).map((value) => value.trim()).filter(Boolean);
  if (draft.allow && !sources.length) throw new Error(t("Enter the trusted LAN source ranges before enabling sharing"));
  const lan = sources.length ? {
    listen: draft.lanAddress.trim(),
    port: integer(draft.lanPort, 1024, 65535, t("LAN port")),
    allowed_source_cidrs: sources,
  } : null;
  if (lan && (!/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(lan.listen) || sources.length > 32)) {
    throw new Error(t("Enter an IPv4 listener and at most 32 trusted source ranges"));
  }
  const preferred = String(draft.port).trim() ? integer(draft.port, 1024, 65535, t("Proxy port")) : null;
  if (lan && lan.port === preferred) throw new Error(t("The local and LAN proxy ports must be different"));
  return {
    preferred_mixed_port: preferred,
    log_level: draft.level,
    tunnel_mtu: integer(draft.mtu, 1280, 9000, "TUN MTU"),
    ...(draft.ipv6DNSInherited && draft.ipv6DNS === draft.initialIPv6DNS ? {} : { ipv6_dns_enabled: draft.ipv6DNS }),
    allow_lan: draft.allow === true,
    lan_proxy: lan,
  };
}

export function acceptNativeRuntimeDraft(prior, value) {
  const limits = { port: 32, level: 16, mtu: 32, lanAddress: 255, lanPort: 32, lanSources: 8192 };
  const keys = [...Object.keys(limits), "ipv6DNS", "allow", "ipv6DNSEdited"].sort();
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== keys.join(",")
    || Object.entries(limits).some(([key, limit]) => typeof value[key] !== "string" || Array.from(value[key]).length > limit)
    || ["ipv6DNS", "allow", "ipv6DNSEdited"].some((key) => typeof value[key] !== "boolean")
    || !RUNTIME_LOG_LEVELS.includes(value.level)) throw new TypeError("Native runtime settings draft is invalid");
  const { ipv6DNSEdited, ...fields } = value;
  return { ...prior, ...fields, ipv6DNSInherited: prior.ipv6DNSInherited && !ipv6DNSEdited };
}

export function createRuntimeSettingsUI({ state, invoke, appendLog, renderPage, refreshRuntime, dismissOtherDialogs, nativeDialog }) {
  let request = 0;
  function validateSnapshot(snapshot) {
    if (!snapshot || typeof snapshot.settings !== "object" || typeof snapshot.effective !== "object"
      || !RUNTIME_LOG_LEVELS.includes(snapshot.settings.log_level)
      || typeof snapshot.settings.allow_lan !== "boolean"
      || (snapshot.settings.ipv6_dns_enabled !== undefined && typeof snapshot.settings.ipv6_dns_enabled !== "boolean")
      || typeof snapshot.effective.ipv6_dns_enabled !== "boolean"
      || !(snapshot.revision === null || typeof snapshot.revision === "string")) {
      throw new TypeError("Runtime settings response is invalid");
    }
  }
  function accept(snapshot) {
    validateSnapshot(snapshot);
    state.runtimeSettings = snapshot;
    state.runtimeSettingsError = null;
    state.toggles.allowLan = snapshot.settings.allow_lan;
    state.toggles.ipv6DNS = snapshot.effective.ipv6_dns_enabled;
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
    const draft = runtimeDraft(state.runtimeSettings.settings, state.runtimeSettings.effective);
    if (enableLAN) draft.allow = true;
    state.runtimeSettingsDialog = { draft, revision: state.runtimeSettings.revision, saving: false, error: null };
    renderPage();
  }
  function close() {
    if (state.runtimeSettingsDialog?.saving) return;
    state.runtimeSettingsDialog = null;
  }
  async function save(settings, revision, dialog = null) {
    if (state.engineMutationBusy || state.migrationHandoff) throw new Error(t("Another network operation is in progress"));
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
      appendLog("info", "settings", t("Runtime settings applied and saved"));
    } catch (error) {
      if (dialog) dialog.error = errorText(error);
      appendLog("error", "settings", t("Runtime settings were not applied: {error}", { error: errorText(error) }));
      await load();
    } finally {
      // A failed candidate may have restored the old core under a new identity.
      // Refresh that state on both outcomes instead of predicting a rollback.
      try { await refreshRuntime(); } catch (error) {
        appendLog("error", "settings", t("Could not refresh runtime status: {error}", { error: errorText(error) }));
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
  async function toggleIPv6DNS(enabled) {
    if (typeof enabled !== "boolean") throw new TypeError("IPv6 DNS must be enabled or disabled");
    if (state.engineMutationBusy || state.migrationHandoff) throw new Error(t("Another network operation is in progress"));
    const snapshot = await invoke("read_runtime_settings_snapshot");
    validateSnapshot(snapshot);
    // A background refresh cannot cancel a user's choice. Bind the write to
    // the exact snapshot read for this action; the backend enforces its revision.
    return save({ ...snapshot.settings, ipv6_dns_enabled: enabled }, snapshot.revision);
  }
  function renderDialog() {
    const dialog = state.runtimeSettingsDialog;
    if (!dialog) { nativeDialog?.sync(null); return ""; }
    if (nativeDialog?.enabled()) {
      const failure = nativeDialog.sync(dialog, runtimeDialogFrame(dialog), {
        onSubmit: (draft) => submitDialog(dialog, draft),
        onClose: () => { if (state.runtimeSettingsDialog === dialog) { close(); renderPage(); } },
        onChange: renderPage,
      });
      // Keep the original page backdrop and its cancellation handler. A native
      // presentation failure is explicit and never represented as a saved form.
      return `<div class="glass-dialog-backdrop" data-runtime-dismiss></div>${failure ? `
        <section class="glass-dialog runtime-settings-dialog" role="dialog" aria-modal="true" aria-label="${escapeHtml(t("Network settings"))}">
          <h2>${escapeHtml(t("Network settings"))}</h2>
          <p class="glass-dialog-copy warning" role="alert">${escapeHtml(failure)}</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-runtime-dismiss${dialog.saving ? " disabled" : ""}>${escapeHtml(t("Cancel"))}</button></div>
        </section>` : ""}`;
    }
    const d = dialog.draft;
    const disabled = dialog.saving ? " disabled" : "";
    return `<div class="glass-dialog-backdrop" data-runtime-dismiss></div>
      <section class="glass-dialog runtime-settings-dialog" role="dialog" aria-modal="true" aria-labelledby="runtime-settings-title">
        <h2 id="runtime-settings-title">${escapeHtml(t("Network settings"))}</h2>
        <p class="glass-dialog-copy">${escapeHtml(t("Changes apply to the current core. Existing connections may reconnect."))}</p>
        <label class="glass-input-label">${escapeHtml(t("Local proxy port"))} <input class="glass-input" data-runtime-field="port" inputmode="numeric" placeholder="${escapeHtml(t("Automatic"))}" value="${escapeHtml(d.port)}"${disabled}></label>
        <label class="glass-input-label">${escapeHtml(t("Log level"))} <select class="glass-input" data-runtime-field="level"${disabled}>${RUNTIME_LOG_LEVELS.map((level) => `<option value="${level}"${d.level === level ? " selected" : ""}>${level}</option>`).join("")}</select></label>
        <label class="glass-input-label">TUN MTU <input class="glass-input" data-runtime-field="mtu" inputmode="numeric" value="${escapeHtml(d.mtu)}"${disabled}></label>
        <label class="glass-input-label"><input type="checkbox" data-runtime-field="ipv6DNS"${d.ipv6DNS ? " checked" : ""}${disabled}> ${escapeHtml(t("Enable IPv6 DNS"))}</label>
        <p class="glass-dialog-copy">${escapeHtml(t("Turn off for a proxy server with a broken IPv6 exit. TUN still captures IPv6 traffic."))}</p>
        <label class="glass-input-label"><input type="checkbox" data-runtime-field="allow"${d.allow ? " checked" : ""}${disabled}> ${escapeHtml(t("Share with trusted LAN devices"))}</label>
        <p class="glass-dialog-copy">${escapeHtml(t("LAN devices use a separate port. Enter the private source networks allowed to use it."))}</p>
        <label class="glass-input-label">${escapeHtml(t("LAN listener"))} <input class="glass-input" data-runtime-field="lanAddress" value="${escapeHtml(d.lanAddress)}"${disabled}></label>
        <label class="glass-input-label">${escapeHtml(t("LAN port"))} <input class="glass-input" data-runtime-field="lanPort" inputmode="numeric" value="${escapeHtml(d.lanPort)}"${disabled}></label>
        <label class="glass-input-label">${escapeHtml(t("Trusted source ranges"))} <textarea class="glass-textarea" data-runtime-field="lanSources" rows="3" placeholder="192.168.1.0/24"${disabled}>${escapeHtml(d.lanSources)}</textarea></label>
        ${dialog.error ? `<p class="glass-dialog-copy warning" role="alert">${escapeHtml(dialog.error)}</p>` : ""}
        <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-runtime-dismiss${disabled}>${escapeHtml(t("Cancel"))}</button><button type="button" class="glass-btn primary" data-runtime-save${disabled}>${dialog.saving ? t("Applying…") : t("Apply")}</button></div>
      </section>`;
  }
  function bindDialog() {
    document.querySelectorAll("[data-runtime-field]").forEach((input) => input.addEventListener("input", () => {
      const dialog = state.runtimeSettingsDialog;
      const key = input.dataset.runtimeField;
      if (!dialog || dialog.saving || !Object.hasOwn(dialog.draft, key)) return;
      dialog.draft[key] = key === "allow" || key === "ipv6DNS" ? input.checked : input.value;
      if (key === "ipv6DNS") dialog.draft.ipv6DNSInherited = false;
    }));
    document.querySelectorAll("[data-runtime-dismiss]").forEach((button) => button.addEventListener("click", () => { close(); renderPage(); }));
    document.querySelectorAll("[data-runtime-save]").forEach((button) => button.addEventListener("click", async () => {
      const dialog = state.runtimeSettingsDialog;
      await submitDialog(dialog);
    }));
  }
  async function submitDialog(dialog, nativeDraft) {
    if (!dialog || state.runtimeSettingsDialog !== dialog || dialog.saving) return;
    try {
      if (nativeDraft !== undefined) dialog.draft = acceptNativeRuntimeDraft(dialog.draft, nativeDraft);
      await save(preferencesFromRuntimeDraft(dialog.draft), dialog.revision, dialog);
    } catch (error) { dialog.error = errorText(error); renderPage(); }
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
  return { load, open, close, save, toggleLAN, toggleIPv6DNS, renderDialog, bindDialog, bindPage };
}
