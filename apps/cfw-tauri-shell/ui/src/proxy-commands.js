// The proxy mode and proxy selection commands. While the engine is Off a
// selection is saved to the profile for the next start.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { controllerActionAllowed, engineIsOff } from "./engine-identity.js";
import { controllerModeFromSnapshot, controllerSelectorFromSnapshot } from "./controller-snapshot.js";
import { isManualProxyGroup } from "./proxies.js";

export function createProxyCommands({ renderPage, enqueueControllerMutation, freshProxyControllerSnapshotAvailable, loadProfilesSnapshot }) {
  /// Pushes a proxy mode to the running engine. It is the only runtime switch the
  /// clash-compatible controller accepts, and it is not a persisted preference, so
  /// nothing is written to the preference store here.
  async function applyProxyMode(mode) {
    if (!["Global", "Rule", "Direct"].includes(mode)) throw new TypeError("Proxy mode is invalid");
    if (!controllerActionAllowed(t("Proxy mode {mode}", { mode: t(mode) }), "mode")) return;
    if (!freshProxyControllerSnapshotAvailable()) {
      appendLog("info", "mode", t("Proxy mode {mode} requires a fresh controller snapshot", { mode: t(mode) }));
      return false;
    }
    const invokeMutation = () => invoke("set_proxy_mode", { mode });
    return enqueueControllerMutation({
      lane: "proxy-mode",
      kind: "mode",
      target: mode,
      source: "mode",
      failureLabel: t("Proxy mode {mode} was not applied", { mode: t(mode) }),
      successMessage: t("Proxy mode switched to {mode}", { mode: t(mode) }),
      breakConnectionsReason: "mode",
      invokeMutation,
      readObserved: controllerModeFromSnapshot,
      publishObserved: (observed) => { state.mode = observed; },
    });
  }

  async function applyProxySelection(groupName, proxyName) {
    if (engineIsOff() && state.savedProfilePolicy) {
      const policy = state.savedProfilePolicy;
      const group = policy.groups.find((item) => item.name === groupName);
      if (state.savedProxySelectionBusy || !group || !isManualProxyGroup(group.type)
        || !group.options.some((item) => item.name === proxyName)) return false;
      state.savedProxySelectionBusy = true;
      try {
        await invoke("select_proxy", { profileId: policy.profileId, group: groupName, proxy: proxyName });
        await loadProfilesSnapshot();
        const observed = state.savedProfilePolicy;
        if (observed?.profileId !== policy.profileId || observed.groups.find((item) => item.name === groupName)?.now !== proxyName) {
          throw new Error("Saved proxy selection could not be confirmed");
        }
        appendLog("info", "proxy", t("Saved {proxyName} for {groupName}; it will apply on the next start", { proxyName: proxyName, groupName: groupName }));
        return true;
      } catch (error) {
        appendLog("error", "proxy", errorText(error));
        return false;
      } finally {
        state.savedProxySelectionBusy = false;
        renderPage();
      }
    }
    const group = state.proxyGroups.find((item) => item.name === groupName);
    if (!group) return false;
    if (!freshProxyControllerSnapshotAvailable()) {
      if (!state.engine.active) {
        controllerActionAllowed(t("Selecting proxy in {groupName}", { groupName: groupName }), "proxy");
      } else {
        appendLog("info", "proxy", t("Proxy selection requires a fresh controller snapshot"));
      }
      return false;
    }
    if (!isManualProxyGroup(group.type)) {
      appendLog("error", "proxy", t("The current proxy group is selected by the engine and is read-only"));
      return false;
    }
    if (!group.options.some((item) => item.name === proxyName)) {
      appendLog("error", "proxy", t("Proxy selection is not an option in the current controller snapshot"));
      return false;
    }
    if (!controllerActionAllowed(t("Selecting proxy in {groupName}", { groupName: groupName }), "proxy")) return false;
    const invokeMutation = () => invoke("select_proxy", { group: groupName, proxy: proxyName });
    return enqueueControllerMutation({
      lane: `proxy-selector:${groupName}`,
      kind: "selector",
      groupName,
      target: proxyName,
      source: "proxy",
      failureLabel: t("Proxy selection {groupName} → {proxyName} was not applied", { groupName: groupName, proxyName: proxyName }),
      successMessage: t("Proxy group {groupName} switched to {proxyName}", { groupName: groupName, proxyName: proxyName }),
      breakConnectionsReason: groupName,
      invokeMutation,
      readObserved: (snapshot) => controllerSelectorFromSnapshot(snapshot, groupName),
      publishObserved: (observed) => {
        const current = state.proxyGroups.find((item) => item.name === groupName);
        if (current && observed !== null) current.now = observed;
      },
    });
  }

  return { applyProxyMode, applyProxySelection };
}
