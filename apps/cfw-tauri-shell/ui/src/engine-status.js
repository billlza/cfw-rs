// The engine status: reading it, applying it, and the startup recovery the
// host offers while its background services restart.
import { state, runtime, defaultEngineStatus } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { normalizeEngineStatus } from "./engine-status-model.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { captureEngineIdentityToken, engineIdentityTokenIsCurrent, engineRuntimeIdentityChanged } from "./engine-identity.js";
import { clearControllerBackedState } from "./controller-snapshot.js";
import { invalidateControllerMutationIntents } from "./controller-intents.js";

export function createEngineStatus({ renderPage, updateStatusBar, cancelDelayTest }) {
  function invalidateEngineBoundState(active) {
    runtime.engineIdentityEpoch += 1;
    invalidateControllerMutationIntents();
    for (const lane of [runtime.connectionsLiveStream, runtime.logLiveStream]) {
      lane.intentEpoch += 1;
      lane.desiredRunning = false;
      lane.binding = null;
    }
    cancelDelayTest();
    state.proxyDelayResults.clear();
    state.proxyDelayMessage = null;
    clearControllerBackedState();
    state.controllerVersion = null;
    state.controllerStatus = active ? "controller loading" : "engine off";
  }

  /// Asks for the host's startup recovery without the user, a few seconds after
  /// a status read that failed in a way the host says a fresh read can resolve,
  /// as it does right after an installation while the background services are
  /// restarting. Each status read decides again; after the last automatic
  /// attempt the page explains what the user can do.
  function scheduleStartupRecovery() {
    const recovery = runtime.startupRecovery;
    if (!state.engine.startupRecoveryAvailable || state.migrationHandoff) {
      if (recovery.timer !== null) {
        window.clearTimeout(recovery.timer);
        recovery.timer = null;
      }
      if (!state.engine.startupRecoveryAvailable) {
        recovery.attempts = 0;
        recovery.exhausted = false;
      }
      return;
    }
    if (recovery.timer !== null || recovery.exhausted) return;
    if (recovery.attempts >= recovery.delays.length) {
      recovery.exhausted = true;
      return;
    }
    const delay = recovery.delays[recovery.attempts];
    recovery.attempts += 1;
    recovery.timer = window.setTimeout(async () => {
      recovery.timer = null;
      if (state.engine.startupRecoveryAvailable && !state.migrationHandoff && !state.engineMutationBusy) {
        try {
          await reconcileStartupServices();
        } catch (error) {
          appendLog("warning", "engine", t("Automatic background service recovery did not succeed yet: {error}", { error: errorText(error) }));
        }
      }
      // The status read inside the recovery decided the next step; with no
      // attempt pending and none left, the page now explains.
      scheduleStartupRecovery();
      renderPage();
    }, delay);
  }

  async function reconcileStartupServices() {
    if (state.engineMutationBusy) throw new Error(t("A network mode change is already in progress"));
    if (state.migrationHandoff || !state.engine.startupRecoveryAvailable) {
      throw new Error(t("Background service recovery is not available in the current state."));
    }
    const requestId = runtime.engineStatusRequestId + 1;
    runtime.engineStatusRequestId = requestId;
    state.engineMutationBusy = true;
    state.engineMutationError = null;
    renderPage();
    try {
      const payload = await invoke("reconcile_startup_services");
      const recovered = normalizeEngineStatus(payload);
      if (recovered.state !== "Off" || recovered.desiredMode !== "off" || recovered.active) {
        throw new Error(t("Background service recovery did not prove the engine is Off."));
      }
      if (requestId === runtime.engineStatusRequestId) applyEngineStatus(payload);
      else await loadEngineStatus();
      appendLog("info", "engine", t("Background service recovery completed."));
    } catch (error) {
      try {
        await loadEngineStatus();
      } catch (refreshError) {
        appendLog("error", "engine", t("Could not refresh mode state after refusal: {error}", { error: errorText(refreshError) }));
      }
      state.engineMutationError = errorText(error).slice(0, 512);
      throw error;
    } finally {
      state.engineMutationBusy = false;
      renderPage();
    }
  }

  /// Applies an engine status envelope, validating the runtime identity before the
  /// dashboard is allowed to say the network is up.
  function applyEngineStatus(payload) {
    const previous = state.engine;
    let next;
    try {
      next = normalizeEngineStatus(payload);
    } catch (error) {
      next = { ...defaultEngineStatus, availabilityReason: errorText(error) };
      appendLog("error", "engine", t("Engine state could not be trusted: {error}", { error: errorText(error) }));
    }
    state.engine = next;
    scheduleStartupRecovery();
    if (engineRuntimeIdentityChanged(previous, next)) {
      invalidateEngineBoundState(next.active);
    } else if (!next.active) {
      // Off is an expected steady state. Repeated snapshots still clear any
      // event/request result that arrived between native status reads.
      clearControllerBackedState();
        state.controllerVersion = null;
      state.controllerStatus = "engine off";
    }
    // Green switches represent verified runtime activity. Pending and failed
    // intentions retain separate retry/cancel actions and never look connected.
    state.toggles.systemProxy = state.engine.systemProxyActive;
    state.toggles.tunMode = state.engine.tunnelActive;
    if (state.engine.active) {
      if (!state.engineStartedAt) state.engineStartedAt = Date.now();
      state.traffic.runtimeSeconds = Math.floor((Date.now() - state.engineStartedAt) / 1000);
    } else {
      state.engineStartedAt = null;
      state.traffic.runtimeSeconds = 0;
    }
    updateStatusBar();
  }

  async function loadEngineStatus() {
    const requestId = runtime.engineStatusRequestId + 1;
    runtime.engineStatusRequestId = requestId;
    try {
      const snapshot = await invoke("engine_snapshot");
      if (requestId !== runtime.engineStatusRequestId) return false;
      applyEngineStatus(snapshot);
    } catch (error) {
      if (requestId !== runtime.engineStatusRequestId) return false;
      state.engine = { ...defaultEngineStatus, availabilityReason: errorText(error) };
      invalidateEngineBoundState(false);
      appendLog("error", "engine", t("Unable to read the engine state: {error}", { error: errorText(error) }));
    }
    try {
      state.geoipStatus = await invoke("geoip_database_status");
    } catch (error) {
      state.geoipStatus = null;
      appendLog("error", "geoip", t("Unable to read the GeoIP database status: {error}", { error: errorText(error) }));
    }
    if (state.engine.active) {
      const token = captureEngineIdentityToken();
      try {
        const version = await invoke("controller_version");
        if (engineIdentityTokenIsCurrent(token)) state.controllerVersion = version;
      } catch (error) {
        if (!engineIdentityTokenIsCurrent(token)) return false;
        state.controllerVersion = null;
        appendLog("error", "controller", t("Unable to read the controller version: {error}", { error: errorText(error) }));
      }
    } else {
      state.controllerVersion = null;
    }
    return true;
  }

  return { applyEngineStatus, loadEngineStatus, reconcileStartupServices };
}
