// The Logs page actions: the request log stream, copying, clearing and searching.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { controllerActionAllowed } from "./engine-identity.js";
import { setLogStreamRunning } from "./live-streams.js";

export function createLogActions({ renderPage, patchLogStream }) {
  const actions = {
    "toggle-log-stream": async () => {
      const pause = !state.logsPaused;
      if (!pause && !controllerActionAllowed(t("Starting request logs"), "logs")) return;
      const previous = state.logsPaused;
      state.logsPaused = pause;
      try {
        const changed = await setLogStreamRunning(!pause);
        if (!changed) return;
        appendLog("info", "logs", t(pause ? "Request logs stopped" : "Request logs started"));
      } catch (error) {
        if (!pause) state.logsPaused = previous;
        appendLog("error", "logs", t("Log stream change failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
    "clear-logs": async () => {
      state.logs = [];
      renderPage();
    },
    "copy-logs": async () => {
      const text = state.logs.map((entry) => {
        const time = entry.time ?? entry.at ?? "";
        const level = entry.level ?? "info";
        const message = entry.message ?? entry.payload ?? String(entry);
        return `[${time}] ${level} ${message}`;
      }).join("\n");
      try {
        await navigator.clipboard.writeText(text || t("(no logs)"));
        appendLog("info", "logs", t("Copied {count} log line(s) to clipboard", { count: state.logs.length }));
      } catch (error) {
        appendLog("warning", "logs", t("Copy logs refused: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
    "reveal-logs": async () => {
      try {
        await invoke("reveal_logs_directory");
        appendLog("info", "logs", state.payload.product.operating_system === "windows"
          ? t("Logs folder opened in File Explorer") : t("Logs folder opened in Finder"));
      } catch (error) {
        appendLog("error", "logs", t("Open Folder failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
  };

  function bindPage() {
    const logSearch = document.querySelector("[data-log-search]");
    if (logSearch) {
      logSearch.addEventListener("input", (event) => {
        state.logSearch = event.currentTarget.value;
        patchLogStream();
      });
    }
  }

  return { actions, bindPage };
}
