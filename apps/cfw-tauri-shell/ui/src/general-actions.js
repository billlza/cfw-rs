// The General page's explanations and shortcuts: what a row means, folders and system settings.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { REASONS } from "./reasons.js";
import { platformPresentation, proxyEnvironmentCommands } from "./platform-presentation.js";

export function createGeneralActions({ renderPage, renderGlassOverlays, automationSettingsUI, runtimeSettingsUI }) {
  const actions = {
    "recover-installation-identity": async () => {
      if (state.engineMutationBusy || state.identityRecoveryRestartRequired) return;
      state.engineMutationBusy = true;
      state.identityRecoveryError = null;
      renderPage();
      try {
        const result = await invoke("recover_installation_identity");
        if (typeof result?.recovered !== "boolean" || result.requires_restart !== true
          || (result.recovered ? result.error !== null : typeof result.error !== "string")) {
          throw new Error("Invalid installation recovery response");
        }
        state.identityRecoveryRestartRequired = true;
        if (result.recovered) {
          await invoke("restart_after_identity_recovery");
        } else {
          state.identityRecoveryError = result.error;
          appendLog("error", "identity-recovery", result.error);
        }
      } catch (error) {
        state.identityRecoveryError = errorText(error);
        appendLog("error", "identity-recovery", state.identityRecoveryError);
      } finally {
        state.engineMutationBusy = state.identityRecoveryRestartRequired;
        renderPage();
      }
    },
    "restart-after-identity-recovery": async () => {
      try {
        await invoke("restart_after_identity_recovery");
      } catch (error) {
        state.identityRecoveryError = errorText(error);
        renderPage();
      }
    },
    "copy-proxy-exports": async () => {
      const port = state.projection.mixedPort;
      if (!port) {
        appendLog("warning", "shell", t("The projected inbound port is unavailable: {value1}", { value1: state.projection.error ?? t("no active profile is selected") }));
        renderPage();
        return;
      }
      try {
        const exports = proxyEnvironmentCommands(state.payload.product.operating_system, port);
        await navigator.clipboard.writeText(exports);
        appendLog("info", "shell", t(platformPresentation(state.payload.product.operating_system).copiedProxyCommands));
      } catch (error) {
        appendLog("warning", "clipboard", errorText(error));
      }
      renderPage();
    },
    "allow-lan-info": async () => {
      state.glassDialog = {
        kind: "info",
        payload: {
          title: t("Allow LAN"),
          body: REASONS.allowLan,
        },
      };
      renderGlassOverlays();
    },
    "tun-info": async () => {
      state.glassDialog = {
        kind: "info",
        payload: {
          title: t("TUN Mode"),
          body: t(platformPresentation(state.payload.product.operating_system).tunnelInfo),
        },
      };
      renderGlassOverlays();
    },
    "mixin-info": async () => {
      state.glassDialog = {
        kind: "info",
        payload: {
          title: t("Mixin"),
          body: REASONS.mixin,
        },
      };
      renderGlassOverlays();
    },
    "tun-restore-dns-info": async () => {
      state.glassDialog = {
        kind: "info",
        payload: { title: t("System DNS"), body: REASONS.restoreDns },
      };
      renderGlassOverlays();
    },
    "open-home-directory": async () => {
      try {
        await invoke("reveal_home_directory");
        appendLog("info", "shell", state.payload.product.operating_system === "windows"
          ? t("Home Directory opened in File Explorer") : t("Home Directory opened in Finder"));
      } catch (error) {
        appendLog("error", "shell", t("Open Folder failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
    "open-windows-startup-settings": async () => {
      try {
        await invoke("open_login_items_settings");
        appendLog("info", "shell", t("Opened Windows Startup settings"));
      } catch (error) {
        appendLog("error", "shell", t("Windows Startup settings could not be opened: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
    "open-automation-settings": async () => { await automationSettingsUI.open(); },
    "open-runtime-settings": async () => { await runtimeSettingsUI.open(); },
    "open-providers": async () => {
      state.activePage = "providers";
      renderPage();
    },
    "open-settings": async () => {
      state.activePage = "settings";
      renderPage();
    },
  };

  return { actions };
}
