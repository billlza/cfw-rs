import { t } from "./i18n.js";
import { escapeHtml, errorText } from "./text-format.js";
import { runtimeDialogDescription, runtimeDialogFrame } from "./native-runtime-settings.js";
import { askForDialog, watchDialogRequests } from "./dialog-requests.js";

export const RUNTIME_LOG_LEVELS = Object.freeze(["trace", "debug", "info", "warn", "error", "fatal", "silent"]);
// Said where the saved settings are found not to be the ones the engine runs
// with: beside the controls that are held for it, and by an action that would
// have built on them.
export const savedSettingsNotInForce = () => t("The saved network settings are not the ones in use. Reload From Disk in Settings shows them, and Apply puts them in use.");
/// Why the controls are held on a snapshot of saved settings that are not in
/// force. Where no change of them can be made now, that is the reason: the
/// advice to apply them could not be followed, and the host refuses a write
/// with this before anything else.
export const savedSettingsHeldFor = (snapshot) => snapshot.change_refused ?? savedSettingsNotInForce();
/// Whether the engine shares the proxy on the LAN, by a snapshot of the
/// settings: what it runs with, as every other switch of them shows.
export const sharesLan = (snapshot) => snapshot.effective.lan_proxy !== null;
// What a write says of the snapshot its settings were built on, under the
// names the snapshot has for it: whether the saved settings were in force,
// and what IPv6 DNS they gave, which is what the form shows where they leave
// it to the profile.
const builtOn = (snapshot, inForce = snapshot.in_force) => ({ in_force: inForce, saved_ipv6_dns_enabled: snapshot.saved_ipv6_dns_enabled });
// The listener of the LAN proxy as a snapshot gives it: none, or its address,
// its port and the source ranges it trusts, which the pages show.
function isLanListener(value) {
  return value === null || (typeof value === "object"
    && typeof value.listen === "string" && Number.isSafeInteger(value.port)
    && Array.isArray(value.allowed_source_cidrs) && value.allowed_source_cidrs.every((range) => typeof range === "string"));
}

// The switches of the settings as the engine runs them, by the names of the
// form's draft.
const runningSwitches = (effective) => ({
  mainlandChinaDirect: effective.mainland_china_direct, dnsLeakProtection: effective.dns_leak_protection,
  webrtcLeakProtection: effective.webrtc_leak_protection, tcpConcurrency: effective.tcp_concurrency,
});

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
    // Not editable fields: carried so saving the form keeps the switches.
    mainlandChinaDirect: settings.mainland_china_direct === true,
    dnsLeakProtection: settings.dns_leak_protection === true,
    webrtcLeakProtection: settings.webrtc_leak_protection === true,
    // On unless the stored settings say otherwise.
    tcpConcurrency: settings.tcp_concurrency !== false,
  };
}

function validateMtuLimits(limits) {
  if (!limits || typeof limits !== "object" || Array.isArray(limits)
    || Object.keys(limits).sort().join(",") !== "maximum,minimum"
    || !Number.isSafeInteger(limits.minimum) || !Number.isSafeInteger(limits.maximum)
    || limits.minimum < 1 || limits.maximum > 65535 || limits.minimum > limits.maximum) {
    throw new TypeError("Runtime settings MTU limits are invalid");
  }
}

export function preferencesFromRuntimeDraft(draft, mtuLimits) {
  validateMtuLimits(mtuLimits);
  if (!RUNTIME_LOG_LEVELS.includes(draft.level)) throw new Error(t("Choose a supported log level"));
  if (typeof draft.ipv6DNS !== "boolean") throw new Error(t("Choose whether to enable IPv6 DNS"));
  if (typeof draft.mainlandChinaDirect !== "boolean" || typeof draft.dnsLeakProtection !== "boolean"
    || typeof draft.webrtcLeakProtection !== "boolean" || typeof draft.tcpConcurrency !== "boolean") {
    throw new TypeError("Runtime settings draft is invalid");
  }
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
  // A listener that is kept for later opens no port, so it may have the
  // number of the local one, as the backend allows. Sharing needs its own.
  if (draft.allow && lan.port === preferred) throw new Error(t("The local and LAN proxy ports must be different"));
  return {
    preferred_mixed_port: preferred,
    log_level: draft.level,
    tunnel_mtu: integer(draft.mtu, mtuLimits.minimum, mtuLimits.maximum, "TUN MTU"),
    ...(draft.ipv6DNSInherited && draft.ipv6DNS === draft.initialIPv6DNS ? {} : { ipv6_dns_enabled: draft.ipv6DNS }),
    allow_lan: draft.allow === true,
    lan_proxy: lan,
    // Absent means off, which keeps the bytes of settings saved before each switch.
    ...(draft.mainlandChinaDirect ? { mainland_china_direct: true } : {}),
    ...(draft.dnsLeakProtection ? { dns_leak_protection: true } : {}),
    ...(draft.webrtcLeakProtection ? { webrtc_leak_protection: true } : {}),
    // Absent means on here, for the same reason.
    ...(draft.tcpConcurrency ? {} : { tcp_concurrency: false }),
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

export function createRuntimeSettingsUI({ state, invoke, appendLog, renderPage, refreshRuntime, dismissOtherDialogs, otherDialogOpen, nativeDialog }) {
  // What this page asks about the settings is numbered as it is asked; a
  // write is numbered when it ends, with the snapshot it returns. `answered`
  // is the latest of them whose answer has arrived.
  let request = 0;
  let answered = 0;
  // How often Reload From Disk was pressed for these settings.
  let reloads = 0;
  // The request whose settings the page shows, and the latest one whose
  // failure holds the controls.
  let shown = 0;
  let failed = 0;
  // Notes that the answer to the request `asked` has arrived, and says whether
  // it still counts: it does not when the answer to something the page asked
  // later is already in.
  function arrived(asked) {
    if (asked < answered) return false;
    answered = asked;
    return true;
  }
  function validateSnapshot(snapshot) {
    if (!snapshot || typeof snapshot.settings !== "object" || typeof snapshot.effective !== "object"
      || !RUNTIME_LOG_LEVELS.includes(snapshot.settings.log_level)
      || typeof snapshot.settings.allow_lan !== "boolean"
      || (snapshot.settings.ipv6_dns_enabled !== undefined && typeof snapshot.settings.ipv6_dns_enabled !== "boolean")
      || typeof snapshot.effective.ipv6_dns_enabled !== "boolean"
      || (snapshot.settings.mainland_china_direct !== undefined && typeof snapshot.settings.mainland_china_direct !== "boolean")
      || typeof snapshot.effective.mainland_china_direct !== "boolean"
      || (snapshot.settings.dns_leak_protection !== undefined && typeof snapshot.settings.dns_leak_protection !== "boolean")
      || typeof snapshot.effective.dns_leak_protection !== "boolean"
      || (snapshot.settings.webrtc_leak_protection !== undefined && typeof snapshot.settings.webrtc_leak_protection !== "boolean")
      || typeof snapshot.effective.webrtc_leak_protection !== "boolean"
      || (snapshot.settings.tcp_concurrency !== undefined && typeof snapshot.settings.tcp_concurrency !== "boolean")
      || typeof snapshot.effective.tcp_concurrency !== "boolean"
      || !isLanListener(snapshot.effective.lan_proxy) || typeof snapshot.in_force !== "boolean"
      || typeof snapshot.saved_ipv6_dns_enabled !== "boolean"
      || !(snapshot.change_refused == null || (typeof snapshot.change_refused === "string" && snapshot.change_refused !== ""))
      || !(snapshot.revision === null || typeof snapshot.revision === "string")) {
      throw new TypeError("Runtime settings response is invalid");
    }
    validateMtuLimits(snapshot.tunnel_mtu_limits);
  }
  function accept(snapshot, asked) {
    validateSnapshot(snapshot);
    shown = asked;
    state.runtimeSettings = snapshot;
    state.runtimeSettingsError = null;
    state.toggles.allowLan = sharesLan(snapshot);
    state.toggles.ipv6DNS = snapshot.effective.ipv6_dns_enabled;
    state.toggles.mainlandChinaDirect = snapshot.effective.mainland_china_direct;
    state.toggles.dnsLeakProtection = snapshot.effective.dns_leak_protection;
    state.toggles.webrtcLeakProtection = snapshot.effective.webrtc_leak_protection;
    state.toggles.tcpConcurrency = snapshot.effective.tcp_concurrency;
    state.logLevel = snapshot.effective.log_level;
  }
  // One read of the settings, for a refresh or for an action, and what the
  // page takes from its answer.
  //
  // Settings are shown only while they answer the last thing the page asked.
  // It asks again because something may have changed, the selected profile
  // for one, and a write ends with settings of its own, so an earlier snapshot
  // may be from before a change and would be shown as what is in force now.
  //
  // A failure has no values that could be out of date. It counts unless the
  // answer to something the page asked later is already in. Settings that
  // were read are such an answer whether or not the page shows them: the read
  // that failed is behind the page then, and so is its failure. A failure
  // that counts holds the controls until the page shows settings again.
  // Settings it does not show end no hold, because the page would go back to
  // what it showed before the failure, and after a failed write that may be
  // settings that were not kept.
  //
  // `snapshot` is there when the host answered with settings, `taken` says
  // whether the page shows them and `captured` is the place of the read in
  // the order; `error` is there when the host refused or answered with
  // something that is no settings, which is a failed read wherever it stands
  // in the order.
  async function read() {
    const captured = ++request;
    try {
      const snapshot = await invoke("read_runtime_settings_snapshot");
      const taken = captured === request;
      if (taken) accept(snapshot, captured);
      else validateSnapshot(snapshot);
      arrived(captured);
      return { snapshot, taken, captured };
    } catch (error) {
      if (arrived(captured)) {
        state.runtimeSettingsError = errorText(error);
        failed = captured;
      }
      return { error };
    }
  }
  // The page's own refresh: whether it now shows what this read returned.
  async function load() {
    return (await read()).taken === true;
  }
  // The settings read for one action of the user: opening the dialog, a
  // switch, the log level, Reload From Disk. The action goes on with exactly
  // the snapshot it read, whose revision the backend enforces on a write, and
  // a read that fails is thrown to it. What the page has read since decides
  // only whether it goes on, by `newestKnown`.
  async function readForAction() {
    const answer = await read();
    if (!answer.snapshot) throw answer.error;
    return answer;
  }
  // The saved settings the page knows once the read of an action has ended:
  // those it read, unless the page has taken newer ones meanwhile, and none
  // while it holds its controls for a read it asked for later that failed.
  // A read that is only under way says nothing yet.
  function newestKnown(answer) {
    if (state.runtimeSettingsError != null && failed > answer.captured) return null;
    return shown > answer.captured ? state.runtimeSettings : answer.snapshot;
  }
  // The settings an action changes one of. It writes the saved ones back with
  // that change, so they have to be the ones the engine runs with: otherwise
  // the write would bring every other difference of the file into force with
  // it, unasked, and none of them is what the page shows. The action goes on
  // with the settings it read, but not once the page holds its controls by
  // the time that read has ended, for newer settings that are not in force or
  // for a read it asked for later that failed: it would offer or write what
  // the page refuses. It is refused then with the reason the page gives beside
  // the controls, whatever its own read found. A read that is only under way
  // takes nothing from it.
  async function loadForEdit() {
    const answer = await readForAction();
    const newest = newestKnown(answer);
    if (newest === null) throw new Error(state.runtimeSettingsError);
    if (!newest.in_force) throw new Error(savedSettingsHeldFor(newest));
    if (!answer.snapshot.in_force) throw new Error(savedSettingsHeldFor(answer.snapshot));
    return answer.snapshot;
  }
  // The form on the settings of a snapshot. It keeps what they were built
  // on, their revision and the basis of that snapshot, for the write of its
  // Apply. Saved settings that are not in force are shown as they are saved,
  // and the form says so.
  //
  // Its Apply puts in use what the form shows and nothing else. IPv6 DNS that
  // the saved settings leave to the profile is shown as they give it, which
  // is not what the engine runs with while an earlier choice is in force
  // there. The profile may be another one by the time of the Apply, which no
  // revision says, so the write says what was shown and the backend refuses
  // it once the profile gives something else. The switches are no fields of
  // the form, so it carries them as the engine runs them. Saved ones that
  // differ are not taken: one that keeps the engine from starting could not
  // be corrected here, and the page holds the switch that could. The backend
  // takes them from the engine once more when the change is made, so a form
  // that stayed open over another change turns none of them back.
  function present(snapshot, enableLAN = false) {
    dismissOtherDialogs();
    const draft = { ...runtimeDraft(snapshot.settings, { ipv6_dns_enabled: snapshot.saved_ipv6_dns_enabled }), ...runningSwitches(snapshot.effective) };
    if (enableLAN) draft.allow = true;
    state.runtimeSettingsDialog = { draft, mtuLimits: { ...snapshot.tunnel_mtu_limits }, revision: snapshot.revision, basis: builtOn(snapshot), saving: false, error: null };
    renderPage();
  }
  // Reload From Disk for these settings, and whether it opened the form.
  // Saved settings the engine does not run with are shown there, where they
  // are applied as they are or corrected first. The reload itself changes
  // nothing of the network, and settings that cannot be applied as they are
  // saved, an MTU beyond what this platform takes for one, have a place to
  // be corrected. A read that fails is thrown, and so is the refusal to
  // change the network now.
  //
  // It can be pressed again while its read is under way. Only the read of the
  // last press opens the form, and none opens it over a dialog that is open by
  // then, this form or another of the app, which this one closes as it opens:
  // what the user has entered there would be gone. Neither does it open once
  // a dialog was asked for after the press, which is still reading then: the
  // form would close that one as it opened. The press asks for no dialog
  // itself, so it takes the place of none that is under way while its read
  // finds nothing to show. It asks once it opens the form.
  //
  // The form shows the saved settings the page knows once that read has
  // ended: those it read, unless the page has taken newer ones meanwhile,
  // and none while the page holds its controls for a read it asked for later
  // that failed. A refresh that is only under way takes nothing from it.
  // Neither does the form open once the user has left Settings, where Reload
  // From Disk is, also when that was as the reload was pressed, with Settings
  // still drawn, or the user is back there by then: it would open over what
  // the user went to, a dialog of that page among them, or came back for. The
  // visit of the page says so, as its name is the same again.
  //
  // Saved settings that no change can be made of now are not shown: the Apply
  // of their form would be refused, and the page says why beside the controls
  // it holds.
  async function reload() {
    const pressed = ++reloads;
    const visit = state.pageVisit;
    const undisturbed = watchDialogRequests(state);
    const snapshot = newestKnown(await readForAction());
    if (pressed !== reloads || !snapshot || snapshot.in_force || snapshot.change_refused) return false;
    if (state.engineMutationBusy || state.migrationHandoff) throw new Error(t("Another network operation is in progress"));
    if (state.activePage !== "settings" || state.pageVisit !== visit) return false;
    if (!undisturbed() || state.runtimeSettingsDialog || otherDialogOpen()) return false;
    askForDialog(state);
    present(snapshot);
    return true;
  }
  // The form from one of its buttons or from the LAN switch, to change
  // settings that are in force. It opens when its read ends, unless the page
  // holds its controls by then, another dialog was asked for meanwhile, or
  // one that opened meanwhile is open: that one may hold what the user has
  // entered there, and this form would take its place.
  async function open(enableLAN = false) {
    if (state.engineMutationBusy || state.migrationHandoff) return;
    const latest = askForDialog(state);
    let snapshot;
    try {
      snapshot = await loadForEdit();
    } catch (error) {
      appendLog("error", "settings", errorText(error));
      renderPage();
      return;
    }
    if (latest()) present(snapshot, enableLAN);
    else renderPage();
  }
  function close() {
    if (state.runtimeSettingsDialog?.saving) return;
    state.runtimeSettingsDialog = null;
  }
  // Writes settings that were built on a snapshot of the revision `revision`.
  // `basis` says what else of that snapshot they were built on, as `builtOn`
  // gives it. A change of one setting is always built on saved settings in
  // force, and the form says it of the settings it was opened on. The backend
  // takes a write only while the saved settings still have that revision
  // and, for one built on settings in force, while they are in force still.
  // Otherwise it would change more than was asked for.
  async function save(settings, revision, basis, dialog = null) {
    if (state.engineMutationBusy || state.migrationHandoff) throw new Error(t("Another network operation is in progress"));
    state.engineMutationBusy = true;
    if (dialog) { dialog.saving = true; dialog.error = null; }
    renderPage();
    let saved = false;
    try {
      const snapshot = await invoke("write_runtime_settings_snapshot", { settings, revision, basis });
      answered = ++request;
      accept(snapshot, answered);
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
    const snapshot = await loadForEdit();
    return save({ ...snapshot.settings, allow_lan: false }, snapshot.revision, builtOn(snapshot, true));
  }
  // One switch of the stored preferences. A background refresh that is under
  // way cannot cancel a user's choice: the write is bound to the exact
  // snapshot read for this action, and the backend enforces its revision. A
  // read that fails ends the action with that failure, and so does a later
  // one that has ended with the controls held.
  async function toggleSwitch(field, enabled) {
    if (typeof enabled !== "boolean") throw new TypeError(`${field} must be enabled or disabled`);
    if (state.engineMutationBusy || state.migrationHandoff) throw new Error(t("Another network operation is in progress"));
    const snapshot = await loadForEdit();
    return save({ ...snapshot.settings, [field]: enabled }, snapshot.revision, builtOn(snapshot, true));
  }
  const toggleIPv6DNS = (enabled) => toggleSwitch("ipv6_dns_enabled", enabled);
  const toggleMainlandChinaDirect = (enabled) => toggleSwitch("mainland_china_direct", enabled);
  const toggleDnsLeakProtection = (enabled) => toggleSwitch("dns_leak_protection", enabled);
  const toggleWebRtcLeakProtection = (enabled) => toggleSwitch("webrtc_leak_protection", enabled);
  const toggleTcpConcurrency = (enabled) => toggleSwitch("tcp_concurrency", enabled);
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
        <p class="glass-dialog-copy">${escapeHtml(runtimeDialogDescription(dialog))}</p>
        <label class="glass-input-label">${escapeHtml(t("Local proxy port"))} <input class="glass-input" data-runtime-field="port" inputmode="numeric" placeholder="${escapeHtml(t("Automatic"))}" value="${escapeHtml(d.port)}"${disabled}></label>
        <label class="glass-input-label">${escapeHtml(t("Log level"))} <select class="glass-input" data-runtime-field="level"${disabled}>${RUNTIME_LOG_LEVELS.map((level) => `<option value="${level}"${d.level === level ? " selected" : ""}>${level}</option>`).join("")}</select></label>
        <label class="glass-input-label">TUN MTU (${dialog.mtuLimits.minimum}–${dialog.mtuLimits.maximum}) <input class="glass-input" data-runtime-field="mtu" inputmode="numeric" value="${escapeHtml(d.mtu)}"${disabled}></label>
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
      await save(preferencesFromRuntimeDraft(dialog.draft, dialog.mtuLimits), dialog.revision, dialog.basis, dialog);
    } catch (error) { dialog.error = errorText(error); renderPage(); }
  }
  function bindPage() {
    document.querySelectorAll("[data-runtime-log-level]").forEach((input) => input.addEventListener("change", async () => {
      const level = input.value;
      if (!RUNTIME_LOG_LEVELS.includes(level)) return;
      try {
        const snapshot = await loadForEdit();
        await save({ ...snapshot.settings, log_level: level }, snapshot.revision, builtOn(snapshot, true));
      } catch (error) { appendLog("error", "settings", errorText(error)); renderPage(); }
    }));
  }
  return { load, reload, open, close, save, toggleLAN, toggleIPv6DNS, toggleMainlandChinaDirect, toggleDnsLeakProtection, toggleWebRtcLeakProtection, toggleTcpConcurrency, renderDialog, bindDialog, bindPage };
}
