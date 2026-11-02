// The Connections page actions: the live stream, closing connections, search and sorting.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { captureEngineIdentityToken, controllerActionAllowed, engineIdentityTokenIsCurrent } from "./engine-identity.js";
import { loadControllerSnapshot } from "./controller-reads.js";
import { setConnectionsStreamRunning } from "./live-streams.js";

export function createConnectionActions({ renderPage, bindConnectionRowEvents }) {
  const actions = {
    "close-all": async () => {
      if (!controllerActionAllowed(t("Closing all connections"), "connection")) return;
      const token = captureEngineIdentityToken();
      const count = state.connections.length;
      state.closingAllConnections = true;
      renderPage();
      try {
        await invoke("close_all_connections");
        if (!engineIdentityTokenIsCurrent(token)) return;
        appendLog("warning", "connection", t("Closed {count} active connections", { count: count }));
        await loadControllerSnapshot(true, token);
      } catch (error) {
        if (!engineIdentityTokenIsCurrent(token)) return;
        state.controllerStatus = "controller offline";
        appendLog("error", "connection", t("Controller close-all failed; keeping local rows: {error}", { error: errorText(error) }));
      } finally {
        if (engineIdentityTokenIsCurrent(token)) state.closingAllConnections = false;
      }
      renderPage();
    },
    "toggle-connection-stream": async () => {
      const pause = !state.connectionPaused;
      if (!pause && !controllerActionAllowed(t("Starting connection stream"), "connections")) return;
      const previous = state.connectionPaused;
      state.connectionPaused = pause;
      try {
        const changed = await setConnectionsStreamRunning(!pause);
        if (!changed) return;
        appendLog("info", "connections", t("Connection stream {value1}", { value1: pause ? "stopped" : "started" }));
      } catch (error) {
        if (!pause) state.connectionPaused = previous;
        appendLog("error", "connections", t("Connection stream change failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
    "close-connection-detail": async () => {
      state.connectionDetailId = null;
      renderPage();
    },
    "clear-connection-search": async () => {
      state.connectionSearch = "";
      renderPage();
    },
  };

  function bindPage() {
    bindConnectionRowEvents(document);

    const connectionSearch = document.querySelector("[data-connection-search]");
    if (connectionSearch) {
      connectionSearch.addEventListener("input", (event) => {
        state.connectionSearch = event.currentTarget.value;
        renderPage();
      });
    }

    document.querySelectorAll("[data-connection-sort]").forEach((button) => {
      button.addEventListener("click", (event) => {
        const sort = event.currentTarget.dataset.connectionSort;
        if (state.connectionSort === sort) {
          state.connectionSortDesc = !state.connectionSortDesc;
        } else {
          state.connectionSort = sort;
          state.connectionSortDesc = false;
        }
        renderPage();
      });
    });

    document.querySelectorAll("[data-copy-text]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        const value = event.currentTarget.dataset.copyText ?? "";
        try {
          await navigator.clipboard.writeText(value);
          appendLog("info", "clipboard", t("Connection field copied"));
        } catch (_error) {
          appendLog("warning", "clipboard", t("Clipboard API refused copy"));
        }
        renderPage();
      });
    });

    document.querySelectorAll("[data-connection-facet]").forEach((button) => {
      button.addEventListener("click", (event) => {
        state.connectionSearch = event.currentTarget.dataset.connectionFacet;
        renderPage();
      });
    });
  }

  return { actions, bindPage };
}
