// Whether each network switch may be turned on now, and why not.
import { state } from "./state.js";
import { modeHasSystemProxy, modeHasTunnel } from "./engine-status-model.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { platformPresentation } from "./platform-presentation.js";

export function engineToggleCapability(key) {
  if ((key === "coreRunning" || key === "systemProxy" || key === "tunMode") && state.migrationHandoff) {
    return {
      available: false,
      label: key === "coreRunning" ? t("Core") : key === "systemProxy" ? t("System Proxy") : t("TUN Mode"),
      reason: t("This window owns legacy CFM maintenance. Use its explicit maintenance or recovery controls."),
    };
  }
  if ((key === "coreRunning" || key === "systemProxy" || key === "tunMode") && state.engine.startupRecoveryAvailable) {
    return {
      available: false,
      label: key === "coreRunning" ? t("Core") : key === "systemProxy" ? t("System Proxy") : t("TUN Mode"),
      reason: t("Recover background services before starting a connection."),
    };
  }
  if (key === "coreRunning") {
    return {
      available: state.engine.localProxyAvailable === true,
      label: t("Core"),
      reason: state.engine.availabilityReason ?? t(platformPresentation(state.payload.product.operating_system).localProxyUnavailable),
    };
  }
  // Turning one integration on while the other is requested asks for the
  // combined mode, which has its own capability and its own reason; it is not
  // the engine's general availability or an earlier failure.
  const presentation = () => platformPresentation(state.payload.product.operating_system);
  const combinationRefused = (alone, otherRequested) => alone && otherRequested
    && state.engine.tunnelSystemProxyAvailable !== true;
  if (key === "systemProxy") {
    const alone = state.engine.systemProxyAvailable === true;
    const refused = combinationRefused(alone, modeHasTunnel(state.engine.desiredMode));
    return {
      available: alone && !refused,
      get label() { return t("System Proxy"); },
      reason: refused
        ? t(presentation().combinedUnavailable)
        : state.engine.availabilityReason ?? t(presentation().systemProxyUnavailable),
    };
  }
  if (key === "tunMode") {
    const alone = state.engine.tunnelAvailable === true;
    const refused = combinationRefused(alone, modeHasSystemProxy(state.engine.desiredMode));
    return {
      available: alone && !refused,
      get label() { return t("TUN Mode"); },
      reason: refused
        ? t(presentation().combinedUnavailable)
        : state.engine.availabilityReason ?? t(presentation().tunnelUnavailable),
    };
  }
  return null;
}

/// Enabling a native network mode requires the corresponding verified
/// capability. Disabling an already-requested mode is always admitted so a
/// failed or newly unavailable target never traps the switch On.
export function engineToggleChangeAllowed(key, checked, source) {
  const capability = engineToggleCapability(key);
  if (capability && state.migrationHandoff) {
    appendLog("info", source, capability.reason);
    return false;
  }
  if (!capability || !checked || capability.available) return true;
  appendLog("info", source, t("{label} cannot be enabled: {reason}", { label: capability.label, reason: capability.reason }));
  return false;
}
