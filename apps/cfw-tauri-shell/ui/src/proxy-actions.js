// The Proxies page actions: groups, the node list, delay tests and the proxy mode.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { captureEngineIdentityToken, controllerActionAllowed, engineIdentityTokenIsCurrent } from "./engine-identity.js";
import { loadControllerSnapshot } from "./controller-reads.js";

export function createProxyActions({
  renderPage, activeProxyGroup, hideTimedOutProxies, revealSelectedProxy, runProxyDelayTest, changeProxyPage,
  slugDomId, cancelDelayTest, applyProxyMode, applyProxySelection,
}) {
  const actions = {
    "scroll-to-selected-proxy": async () => {
      const group = activeProxyGroup();
      const selected = group?.now;
      if (!selected) {
        appendLog("warning", "proxy", t("No selected proxy to scroll to"));
        return;
      }
      state.toggles.showProxiesList = true;
      state.proxyFilter = "";
      state.proxyGroupHideTimeouts.set(group.name, false);
      state.proxyBlinkNode = selected;
      revealSelectedProxy(selected);
      renderPage();
      requestAnimationFrame(() => {
        const card = document.querySelector(`[data-proxy-node="${CSS.escape(selected)}"]`);
        card?.scrollIntoView({ block: "center", behavior: "smooth" });
      });
      setTimeout(() => {
        if (state.proxyBlinkNode === selected) {
          state.proxyBlinkNode = null;
          if (state.activePage === "proxies") renderPage();
        }
      }, 1200);
    },
    "toggle-hide-timed-out": async () => {
      const group = activeProxyGroup();
      if (group) state.proxyGroupHideTimeouts.set(group.name, !hideTimedOutProxies(group));
      renderPage();
    },
    "toggle-hide-unavailable": async () => {
      state.toggles.hideUnavailable = !state.toggles.hideUnavailable;
      state.proxyGroupHideTimeouts.clear();
      renderPage();
    },
    "toggle-show-proxies": async () => {
      state.toggles.showProxiesList = !(state.toggles.showProxiesList !== false);
      renderPage();
    },
    "toggle-proxy-filter": async () => {
      state.toggles.showProxyFilter = !state.toggles.showProxyFilter;
      if (!state.toggles.showProxyFilter) state.proxyFilter = "";
      renderPage();
    },
    "break-proxy-connections": async () => {
      if (!controllerActionAllowed(t("Breaking proxy connections"), "proxy")) return;
      const token = captureEngineIdentityToken();
      const count = state.connections.length;
      try {
        await invoke("close_all_connections");
        if (!engineIdentityTokenIsCurrent(token)) return;
        appendLog("warning", "proxy", t("Broke {count} connection(s)", { count: count }));
        await loadControllerSnapshot(true, token);
      } catch (error) {
        if (!engineIdentityTokenIsCurrent(token)) return;
        appendLog("error", "proxy", t("Break connections failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
    "delay-test": async () => {
      await runProxyDelayTest();
      renderPage();
    },
    "reload-proxies": async () => {
      if (!controllerActionAllowed(t("Reloading proxies"), "proxy")) return;
      const live = await loadControllerSnapshot();
      appendLog(live ? "info" : "error", "proxy", live ? "Controller snapshot reloaded" : t("Controller unavailable; keeping local data"));
      renderPage();
    },
  };

  function bindPage() {
    document.querySelectorAll("[data-proxy-page]").forEach((button) => button.addEventListener("click", () => {
      changeProxyPage(Number(button.dataset.proxyPage));
      renderPage();
    }));

    const proxyFilter = document.querySelector("[data-proxy-filter]");
    if (proxyFilter) {
      proxyFilter.addEventListener("input", (event) => {
        state.proxyFilter = event.currentTarget.value;
        renderPage();
      });
    }

    document.querySelectorAll("[data-collapse-group]").forEach((button) => {
      button.addEventListener("click", (event) => {
        const group = event.currentTarget.dataset.collapseGroup;
        if (state.collapsedProxyGroups.has(group)) {
          state.collapsedProxyGroups.delete(group);
        } else {
          state.collapsedProxyGroups.add(group);
        }
        renderPage();
      });
    });

    document.querySelectorAll("[data-scroll-group]").forEach((button) => {
      button.addEventListener("click", (event) => {
        const group = event.currentTarget.dataset.scrollGroup;
        document.getElementById(`proxy-group-${slugDomId(group)}`)?.scrollIntoView({ block: "start", behavior: "smooth" });
      });
    });

    document.querySelectorAll("[data-proxy-group-tab]").forEach((button) => {
      button.addEventListener("click", (event) => {
        cancelDelayTest();
        state.activeProxyGroup = event.currentTarget.dataset.proxyGroupTab;
        renderPage();
      });
    });

    document.querySelectorAll("[data-mode]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        await applyProxyMode(event.currentTarget.dataset.mode);
        renderPage();
      });
    });

    document.querySelectorAll("[data-group][data-node]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        await applyProxySelection(
          event.currentTarget.dataset.group,
          event.currentTarget.dataset.node,
        );
        renderPage();
      });
    });
  }

  return { actions, bindPage };
}
