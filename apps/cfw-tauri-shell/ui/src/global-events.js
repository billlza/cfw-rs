// Window-wide input: Escape, the delegated clicks of every action control and
// log filter, and the keyboard shortcuts.
import { state, runtime, pageById } from "./state.js";
import { errorText } from "./text-format.js";
import { modeHasSystemProxy, modeHasTunnel } from "./engine-status-model.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";

export function createGlobalEvents({
  editingRender, followWindowResize, overlayOpen, closeGlassOverlays, handleAction, applyProxyMode, applyToggle, renderPage,
  patchLogStream,
}) {
  function bindGlobalEvents() {
    if (runtime.globalEventsBound) return;
    runtime.globalEventsBound = true;
    editingRender.bind();
    window.addEventListener("resize", followWindowResize);

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && overlayOpen()) {
        event.preventDefault();
        closeGlassOverlays();
      }
    });

    document.addEventListener("click", (event) => {
      const eventTarget = event.target instanceof Element ? event.target : event.target?.parentElement;
      const filter = eventTarget?.closest("[data-log-filter]");
      if (filter) {
        event.preventDefault();
        const next = filter.dataset.logFilter || "all";
        if (state.logFilter === next) return;
        state.logFilter = next;
        document.querySelectorAll("[data-log-filter]").forEach((button) => {
          const selected = button.dataset.logFilter === state.logFilter;
          button.classList.toggle("selected", selected);
          button.setAttribute("aria-pressed", String(selected));
        });
        patchLogStream();
        return;
      }
      const target = eventTarget?.closest("[data-action]");
      if (!target) return;
      event.preventDefault();
      event.stopPropagation();
      handleAction(target.dataset.action).catch((error) => {
        appendLog("error", "ui", errorText(error));
        renderPage();
      });
    });

    document.addEventListener("keydown", (event) => {
      const key = event.key.toLowerCase();
      const usesCommand = event.metaKey || event.ctrlKey;
      if (!usesCommand || event.altKey) return;

      const target = event.target;
      const isEditable = target instanceof HTMLInputElement
        || target instanceof HTMLTextAreaElement
        || target instanceof HTMLSelectElement
        || target?.isContentEditable;
      const pageShortcuts = {
        "1": "general",
        "2": "proxies",
        "3": "profiles",
        "4": "logs",
        "5": "connections",
        "6": "settings",
      };
      if (!isEditable && pageShortcuts[key]) {
        event.preventDefault();
        state.activePage = pageShortcuts[key];
        appendLog("info", "shortcut", t("Opened {value1}", { value1: pageById(state.activePage).title }));
        renderPage();
        return;
      }
      if (isEditable) return;

      const shortcutAction = {
        g: () => applyProxyMode("Global"),
        r: () => applyProxyMode("Rule"),
        d: () => applyProxyMode("Direct"),
        p: () => applyToggle("systemProxy", !modeHasSystemProxy(state.engine.desiredMode), "shortcut"),
        t: () => applyToggle("tunMode", !modeHasTunnel(state.engine.desiredMode), "shortcut"),
        s: () => handleAction("save-settings"),
      }[key];
      if (shortcutAction) {
        event.preventDefault();
        shortcutAction().catch((error) => {
          appendLog("error", "shortcut", errorText(error));
          renderPage();
        });
      }
    });
  }

  return { bindGlobalEvents };
}
