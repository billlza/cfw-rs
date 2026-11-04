// Every switch of the dashboard: network modes, persisted preferences,
// runtime settings and session-only view options.
import { state, runtime } from "./state.js";
import { engineStateLabel } from "./engine-status-model.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { engineToggleChangeAllowed } from "./engine-capability.js";
import { loadControllerSnapshotWithRetry } from "./controller-reads.js";
import { loadNetworkDiagnostics } from "./system-info.js";

/// Session-only view options. The 0.4.0 preference store has no field for them,
/// so they change what this window shows and are never written to disk.
const SESSION_TOGGLES = new Set(["breakOnProxyChange", "hideUnavailable", "showProcess"]);

const PERSISTED_TOGGLES = new Set([
  "startAtLogin",
  "silentStart",
  "checkForUpdates",
  "retainWindowBounds",
]);

export function createToggles({ renderPage, runtimeSettingsUI, applyEngineStatus, loadEngineStatus, loadRuntimeProjection, applyPersistedSettings, persistedSettingsFromUi, loadSettingsSnapshot }) {
  async function applyUiToggle(key, checked) {
    try {
      await applyToggle(key, checked, "ui");
    } catch (error) {
      appendLog("error", "ui", t("{key} refused: {error}", { key, error: errorText(error) }));
    }
    renderPage();
  }

  async function applyToggle(key, checked, source) {
    if (key === "allowLan") return runtimeSettingsUI.toggleLAN(checked);
    if (key === "ipv6DNS") return runtimeSettingsUI.toggleIPv6DNS(checked);
    if (key === "mainlandChinaDirect") return runtimeSettingsUI.toggleMainlandChinaDirect(checked);
    if (key === "dnsLeakProtection") return runtimeSettingsUI.toggleDnsLeakProtection(checked);
    const isEngineMutation = key === "coreRunning" || key === "systemProxy" || key === "tunMode";
    if (PERSISTED_TOGGLES.has(key) && state.settingsUnavailableReason) {
      throw new Error(state.settingsUnavailableReason);
    }
    if (isEngineMutation && !engineToggleChangeAllowed(key, checked, source)) {
      renderPage();
      return false;
    }
    if (isEngineMutation && state.engineMutationBusy) {
      throw new Error("A network mode change is already in progress");
    }
    const previous = state.toggles[key];
    if (!isEngineMutation) state.toggles[key] = checked;
    const engineRequestId = isEngineMutation ? runtime.engineStatusRequestId + 1 : null;
    if (isEngineMutation) {
      runtime.engineStatusRequestId = engineRequestId;
      state.engineMutationBusy = true;
      state.engineMutationError = null;
      renderPage();
    }
    try {
      if (key === "coreRunning") {
        const status = await invoke("set_core_enabled", { enabled: checked });
        if (engineRequestId === runtime.engineStatusRequestId) applyEngineStatus(status);
        else await loadEngineStatus();
        await loadRuntimeProjection();
        if (state.engine.active) await loadControllerSnapshotWithRetry(6, 500);
      } else if (key === "systemProxy") {
        const status = await invoke("set_system_proxy_enabled", { enabled: checked });
        if (engineRequestId === runtime.engineStatusRequestId) applyEngineStatus(status);
        else await loadEngineStatus();
        await loadNetworkDiagnostics();
        await loadRuntimeProjection();
        if (state.engine.active) await loadControllerSnapshotWithRetry(6, 500);
      } else if (key === "tunMode") {
        const status = await invoke("set_tun_enabled", { enabled: checked });
        if (engineRequestId === runtime.engineStatusRequestId) applyEngineStatus(status);
        else await loadEngineStatus();
        await loadRuntimeProjection();
        if (state.engine.active) await loadControllerSnapshotWithRetry(12, 500);
      } else if (key === "startAtLogin") {
        const snapshot = await invoke("set_launch_at_login_enabled", { enabled: checked });
        applyPersistedSettings(snapshot);
      } else if (SESSION_TOGGLES.has(key)) {
        appendLog("info", source, t("{key} changed to {value2} for this session", { key: key, value2: checked ? "on" : "off" }));
        return;
      } else if (PERSISTED_TOGGLES.has(key)) {
        const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
        applyPersistedSettings(snapshot);
      } else {
        // Every switch is dispatched above; an unknown key never reports success.
        throw new TypeError("Unknown setting switch");
      }
      appendLog("info", source, isEngineMutation
        ? t("{key} request completed; engine {state}", { key: key, state: engineStateLabel(state.engine) })
        : t("{key} changed to {value2}", { key: key, value2: checked ? "on" : "off" }));
      return true;
    } catch (error) {
      state.toggles[key] = previous;
      if (key === "startAtLogin") {
        try {
          await loadSettingsSnapshot();
        } catch (refreshError) {
          appendLog("error", "settings", t("Could not refresh the Login Item state after refusal: {error}", { error: errorText(refreshError) }));
        }
      }
      if (isEngineMutation) {
        try {
          await loadEngineStatus();
        } catch (refreshError) {
          appendLog("error", "engine", t("Could not refresh mode state after refusal: {error}", { error: errorText(refreshError) }));
        }
        state.engineMutationError = errorText(error).slice(0, 512);
      }
      throw error;
    } finally {
      if (isEngineMutation) {
        state.engineMutationBusy = false;
        renderPage();
      }
    }
  }

  return { applyUiToggle, applyToggle };
}
