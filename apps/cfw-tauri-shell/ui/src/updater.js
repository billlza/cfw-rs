import { invoke } from "./bridge.js";
import { store } from "./store.js";
import { appendLog } from "./streams.js";

export function acceptUpdateInfo(payload) {
  if (!payload || typeof payload !== "object") throw new TypeError("Native update payload is invalid");
  const info = {
    available: payload.available === true,
    current: typeof payload.current === "string" ? payload.current.slice(0, 64) : null,
    version: typeof payload.version === "string" ? payload.version.slice(0, 64) : null,
    notes: typeof payload.notes === "string" ? payload.notes.slice(0, 2048) : null,
  };
  store.update({ updateInfo: info });
  return info;
}

export async function checkForUpdates() {
  const info = acceptUpdateInfo(await invoke("check_for_updates"));
  appendLog("info", "updater", info.available ? `Update ${info.version} is available` : "Application is up to date");
  return info;
}

export async function installUpdate() {
  const info = store.get().updateInfo;
  if (!info?.available) throw new TypeError("No verified update is available");
  store.update({ busyAction: "install-update" });
  try {
    await invoke("install_available_update", { expectedVersion: info.version });
    appendLog("info", "updater", "Signed update installed; restart is required");
  } finally {
    store.update({ busyAction: null });
  }
}

export async function cancelUpdateDownload() {
  const result = await invoke("cancel_update_install");
  if (!result || typeof result !== "object" || result.cancelled !== true) {
    throw new TypeError("No cancellable update download is active");
  }
  appendLog("info", "updater", "Update download cancellation requested");
}
