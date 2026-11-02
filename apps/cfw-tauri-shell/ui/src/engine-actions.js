// The actions on the network modes of the engine: start, stop, retry, cancel and recovery.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { captureEngineIdentityToken, controllerActionAllowed, engineIdentityTokenIsCurrent } from "./engine-identity.js";

export function createEngineActions({ renderPage, reconcileStartupServices, applyToggle, applyUiToggle }) {
  const actions = {
    "reconcile-startup-services": () => reconcileStartupServices(),
    "retry-system-proxy": async () => {
      await applyToggle("systemProxy", true, "explicit retry");
      renderPage();
    },
    "toggle-core": async () => {
      await applyToggle("coreRunning", state.engine.desiredMode === "off", "core");
      renderPage();
    },
    "cancel-system-proxy": async (action) => {
      await applyToggle(action === "cancel-system-proxy" ? "systemProxy" : "tunMode", false, "cancel request");
      renderPage();
    },
    "cancel-tun-mode": (action) => actions["cancel-system-proxy"](action),
    "retry-tun-mode": async () => {
      try {
        const admitted = await applyToggle("tunMode", true, "explicit retry");
        if (!admitted) {
          renderPage();
          return;
        }
        if (state.engine.state === "AwaitingApproval") {
          await invoke("open_login_items_settings");
          appendLog("info", "shell", t("Opened System Settings › General › Login Items & Extensions"));
        }
      } catch (error) {
        appendLog("error", "engine", t("TUN retry failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
    "flush-fake-ip-cache": async () => {
      if (!controllerActionAllowed(t("Fake IP cache flush"), "cache")) return;
      const token = captureEngineIdentityToken();
      try {
        await invoke("flush_fake_ip_cache");
        if (!engineIdentityTokenIsCurrent(token)) return;
        appendLog("info", "cache", t("Fake IP cache flushed through the engine controller"));
      } catch (error) {
        if (!engineIdentityTokenIsCurrent(token)) return;
        state.controllerStatus = "controller offline";
        appendLog("error", "cache", t("Fake IP cache flush failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
  };

  function bindPage() {
    document.querySelectorAll("[data-toggle]").forEach((input) => {
      input.addEventListener("change", async (event) => {
        const key = event.currentTarget.dataset.toggle;
        const checked = event.currentTarget.checked;
        await applyUiToggle(key, checked);
      });
    });
  }

  return { actions, bindPage };
}
