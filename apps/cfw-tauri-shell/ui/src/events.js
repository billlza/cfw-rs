import { listen } from "./bridge.js";
import { confirmAction } from "./dialogs.js";
import {
  cleanupLegacyService,
  prepareLegacyCutover,
  refreshEngineState,
  setEngineMode,
} from "./engine.js";
import { errorMessage, formatUpdateProgress } from "./format.js";
import {
  deleteProfile,
  closeProfileCredentialSetup,
  cancelCredentialGc,
  commitCredentialGc,
  importProfileFile,
  loadProfiles,
  openProfileCredentialSetup,
  previewCredentialGc,
  provisionProfileCredentials,
  selectProfile,
} from "./profiles.js";
import { acceptSettingsSnapshot, savePreferences } from "./settings.js";
import { NAV_IDS } from "./state.js";
import { store } from "./store.js";
import { appendLog, logFailure, summarizeEngineEvent } from "./streams.js";
import {
  acceptUpdateInfo,
  cancelUpdateDownload,
  checkForUpdates,
  installUpdate,
} from "./updater.js";
import { invoke } from "./bridge.js";

function reportError(source, error) {
  const message = errorMessage(error);
  store.update({ fatalError: message });
  logFailure(source, error);
}

async function runExclusive(name, operation) {
  if (store.get().busyAction) throw new Error("Another operation is already running");
  store.update({ busyAction: name, fatalError: null });
  try {
    return await operation();
  } finally {
    store.update({ busyAction: null });
  }
}

function readPreferencesForm() {
  const form = document.querySelector("[data-preferences-form]");
  if (!(form instanceof HTMLFormElement)) throw new TypeError("Preferences form is unavailable");
  const formData = new FormData(form);
  return {
    theme: formData.get("theme"),
    fontFamily: formData.get("fontFamily"),
    retainWindowBounds: formData.get("retainWindowBounds") === "on",
    launchAtLogin: formData.get("launchAtLogin") === "on",
    silentStart: formData.get("silentStart") === "on",
    checkForUpdates: formData.get("checkForUpdates") === "on",
  };
}

async function dispatchAction(action, element, callbacks) {
  if (action === "set-engine-mode") {
    await setEngineMode(element.dataset.mode);
    return;
  }
  if (action === "cleanup-legacy") {
    const requiresDnsReview = store.get().legacyRetirement.action === "review_dns";
    const confirmed = await confirmAction(
      "Switch away from the existing VPN?",
      requiresDnsReview
        ? "First review DNS for every active service in System Settings › Network › Details › DNS. Continuing permanently retires the old helper and may briefly interrupt this connection. The prepared replacement starts immediately after verified cleanup. There is no fallback to the old helper if the new start fails."
        : "This is a one-way cutover. It permanently retires the old privileged network service, then immediately starts the exact prepared replacement. The connection may be interrupted briefly, and there is no fallback to the old helper if the new start fails.",
      requiresDnsReview ? "Reviewed — Cut Over" : "Cut Over",
    );
    if (confirmed) await cleanupLegacyService(requiresDnsReview);
    return;
  }
  if (action === "prepare-legacy-cutover") {
    await prepareLegacyCutover(element.dataset.mode);
    return;
  }
  if (action === "delete-profile") {
    const id = element.dataset.profileId;
    const profile = store.get().profiles.find((entry) => entry.id === id);
    if (!profile) throw new TypeError("Profile does not exist");
    const confirmed = await confirmAction("Delete profile?", `Delete ${profile.name}? This cannot be undone.`, "Delete");
    if (confirmed) await runExclusive("delete-profile", () => deleteProfile(id));
    return;
  }
  if (action === "select-profile") {
    const id = element.dataset.profileId;
    await runExclusive("select-profile", () => selectProfile(id));
    return;
  }
  if (action === "configure-profile-credentials") {
    const id = element.dataset.profileId;
    await runExclusive("configure-profile-credentials", () => openProfileCredentialSetup(id));
    return;
  }
  if (action === "cancel-profile-credentials") {
    closeProfileCredentialSetup();
    return;
  }
  if (action === "provision-profile-credentials") {
    const profileId = element.dataset.profileId;
    const form = document.querySelector("[data-credential-form]");
    if (!(form instanceof HTMLFormElement) || form.dataset.profileId !== profileId) {
      throw new TypeError("Credential form does not match the requested profile");
    }
    const inputs = [...form.querySelectorAll("[data-credential-secret]")];
    const entries = inputs.map((input, index) => {
      if (!(input instanceof HTMLInputElement)
        || input.dataset.credentialIndex !== String(index)) {
        throw new TypeError("Credential form order is invalid");
      }
      return {
        id: input.dataset.credentialId,
        kind: input.dataset.credentialKind,
        secret: input.value,
      };
    });
    try {
      await runExclusive(
        "provision-profile-credentials",
        () => provisionProfileCredentials(profileId, entries),
      );
    } finally {
      for (const input of inputs) input.value = "";
      for (const entry of entries) entry.secret = "";
    }
    return;
  }
  if (action === "preview-credential-gc") {
    await runExclusive("preview-credential-gc", () => previewCredentialGc());
    return;
  }
  if (action === "cancel-credential-gc") {
    await runExclusive(
      "cancel-credential-gc",
      () => cancelCredentialGc(element.dataset.previewId),
    );
    return;
  }
  if (action === "commit-credential-gc") {
    const preview = store.get().credentialGcPreview;
    if (!preview || preview.previewId !== element.dataset.previewId) {
      throw new TypeError("Credential cleanup preview is missing or stale");
    }
    const confirmed = await confirmAction(
      "Delete unused credentials?",
      `Permanently delete ${preview.orphanCount} Keychain credential reference${preview.orphanCount === 1 ? "" : "s"}? The repository and vault revision will be revalidated, and any change cancels the deletion.`,
      "Delete Credentials",
    );
    if (confirmed) {
      await runExclusive(
        "commit-credential-gc",
        () => commitCredentialGc(preview.previewId),
      );
    }
    return;
  }
  if (action === "save-preferences") {
    await runExclusive("save-preferences", () => savePreferences(readPreferencesForm()));
    return;
  }
  if (action === "clear-logs") {
    store.clearLogs();
    return;
  }
  if (action === "check-updates") {
    await runExclusive("check-updates", checkForUpdates);
    return;
  }
  if (action === "install-update") {
    await installUpdate();
    return;
  }
  if (action === "cancel-update") {
    await cancelUpdateDownload();
    return;
  }
  if (action === "quit-app") {
    await invoke("quit_app");
    return;
  }
  if (action === "reload") {
    await callbacks.reload();
  }
}

export function bindDomEvents(callbacks) {
  const clickHandler = async (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const nav = target.closest("[data-nav-id]");
    if (nav && NAV_IDS.has(nav.dataset.navId)) {
      store.update({ activePage: nav.dataset.navId, fatalError: null });
      return;
    }
    const actionElement = target.closest("[data-action]");
    if (!actionElement || actionElement.disabled) return;
    try {
      await dispatchAction(actionElement.dataset.action, actionElement, callbacks);
    } catch (error) {
      reportError(actionElement.dataset.action ?? "ui", error);
    }
  };

  const changeHandler = async (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const input = target?.closest("[data-profile-file]");
    if (!(input instanceof HTMLInputElement) || !input.files?.length) return;
    try {
      await runExclusive("import-profile-file", () => importProfileFile(input.files[0]));
    } catch (error) {
      reportError("import-profile-file", error);
    } finally {
      input.value = "";
    }
  };

  document.addEventListener("click", clickHandler);
  document.addEventListener("change", changeHandler);
  return () => {
    document.removeEventListener("click", clickHandler);
    document.removeEventListener("change", changeHandler);
  };
}

export async function bindNativeEvents() {
  const disposers = [];
  try {
    disposers.push(await listen("cfw://page", (event) => {
      if (typeof event.payload === "string" && NAV_IDS.has(event.payload)) {
        store.update({ activePage: event.payload });
      }
    }));
    disposers.push(await listen("cfw://settings-changed", (event) => {
      try {
        acceptSettingsSnapshot(event.payload);
      } catch (error) {
        reportError("settings-event", error);
      }
    }));
    disposers.push(await listen("cfw://update-available", (event) => {
      try {
        acceptUpdateInfo(event.payload);
      } catch (error) {
        reportError("update-event", error);
      }
    }));
    disposers.push(await listen("cfw://update-progress", (event) => {
      const message = formatUpdateProgress(event.payload);
      if (message) appendLog("info", "updater", message);
    }));
    disposers.push(await listen("cfw://engine-snapshot", () => {
      refreshEngineState()
        .then(() => loadProfiles())
        .catch((error) => reportError("engine-event", error));
    }));
    disposers.push(await listen("cfw://engine-event", (event) => {
      appendLog("info", "engine", summarizeEngineEvent(event.payload));
      refreshEngineState().catch((error) => reportError("engine-event", error));
    }));
  } catch (error) {
    for (const dispose of disposers) dispose();
    throw error;
  }
  return () => disposers.forEach((dispose) => dispose());
}
