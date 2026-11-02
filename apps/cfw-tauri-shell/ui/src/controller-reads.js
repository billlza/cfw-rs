// Reads from the running engine's controller. A read is bound to the engine
// identity it started with, and its result is dropped once that identity ends.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke, sleep } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { captureEngineIdentityToken, engineIdentityTokenIsCurrent } from "./engine-identity.js";
import { applyControllerSnapshot, clearControllerBackedState } from "./controller-snapshot.js";
import { applyPendingControllerIntents } from "./controller-intents.js";

export async function closeConnectionsAfterProxyChange(
  reason,
  token = captureEngineIdentityToken(),
  publishAllowed = () => true,
) {
  if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
  const count = state.connections.length;
  if (!count) return true;
  try {
    await invoke("close_all_connections");
    if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
    state.connections = [];
    state.connectionStream.rows = new Map();
    appendLog("warning", "connection", t("Closed {count} connection(s) after {reason} switch", { count: count, reason: reason }));
    return true;
  } catch (error) {
    if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
    state.controllerStatus = "controller offline";
    appendLog("error", "connection", t("Connection cleanup after {reason} switch failed: {error}", { reason: reason, error: errorText(error) }));
    return false;
  }
}

function resetControllerStateForInactiveEngine() {
  clearControllerBackedState();
  state.controllerStatus = "engine off";
}

export async function loadControllerSnapshot(
  reportFailure = true,
  token = captureEngineIdentityToken(),
  publishAllowed = () => true,
  observe = null,
) {
  if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) {
    if (!state.engine.active) resetControllerStateForInactiveEngine();
    return false;
  }
  try {
    const snapshot = await invoke("controller_snapshot");
    if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
    if (!snapshot) {
      clearControllerBackedState();
      state.controllerStatus = "controller offline";
      if (reportFailure) appendLog("error", "controller", t("Running engine returned no controller snapshot"));
      return false;
    }
    if (observe) observe(snapshot);
    applyControllerSnapshot(snapshot);
    applyPendingControllerIntents();
    invoke("refresh_tray_menu").catch((error) => {
      if (engineIdentityTokenIsCurrent(token) && publishAllowed()) {
        appendLog("error", "tray", t("Tray refresh failed: {error}", { error: errorText(error) }));
      }
    });
    return true;
  } catch (error) {
    if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
    clearControllerBackedState();
    state.controllerStatus = "controller offline";
    if (reportFailure) appendLog("error", "controller", errorText(error));
    return false;
  }
}

export async function loadControllerSnapshotWithRetry(attempts = 4, delayMs = 600) {
  const token = captureEngineIdentityToken();
  if (!engineIdentityTokenIsCurrent(token)) {
    resetControllerStateForInactiveEngine();
    return false;
  }
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (!engineIdentityTokenIsCurrent(token)) return false;
    const finalAttempt = attempt + 1 === attempts;
    if (await loadControllerSnapshot(finalAttempt, token)) return true;
    if (!engineIdentityTokenIsCurrent(token)) return false;
    if (attempt + 1 < attempts) await sleep(delayMs);
  }
  return false;
}

export async function loadRulesSnapshot(token = captureEngineIdentityToken()) {
  if (!engineIdentityTokenIsCurrent(token)) {
    if (!state.engine.active) state.rules = [];
    return false;
  }
  try {
    const snapshot = await invoke("rules_snapshot");
    if (!engineIdentityTokenIsCurrent(token)) return false;
    const rules = Array.isArray(snapshot?.rules) ? snapshot.rules : [];
    state.rules = rules.map((rule) => ({
      index: rule.index == null ? "unavailable" : String(rule.index),
      type: rule.kind ?? rule.type ?? "",
      payload: rule.payload ?? "",
      proxy: rule.proxy ?? "",
      provider: rule.provider ?? "",
      hits: rule.hits == null ? "unavailable" : String(rule.hits),
      size: rule.size ?? "unavailable",
      extra: rule.extra ?? {},
    }));
    return true;
  } catch (error) {
    if (!engineIdentityTokenIsCurrent(token)) return false;
    state.rules = [];
    appendLog("error", "rules", errorText(error));
    return false;
  }
}
