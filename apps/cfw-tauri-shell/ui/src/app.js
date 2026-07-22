import { invoke } from "./bridge.js";
import { node, replaceChildren } from "./dom.js";
import { bindDomEvents, bindNativeEvents } from "./events.js";
import { refreshEngineState } from "./engine.js";
import { errorMessage, formatTimestamp } from "./format.js";
import { renderPage } from "./pages/index.js";
import { loadProfiles } from "./profiles.js";
import { loadSettings } from "./settings.js";
import { NAV_ITEMS } from "./state.js";
import { store } from "./store.js";
import { logFailure } from "./streams.js";

function renderNavigation(state) {
  return NAV_ITEMS.map((item) => node("button", {
    className: `nav-item ${state.activePage === item.id ? "active" : ""}`,
    text: item.title,
    type: "button",
    dataset: { navId: item.id },
    attributes: { "aria-current": state.activePage === item.id ? "page" : "false" },
  }));
}

function renderStatus(state) {
  const activeItem = NAV_ITEMS.find(({ id }) => id === state.activePage) ?? NAV_ITEMS[0];
  document.title = state.product?.name ?? "Clash for Mac";
  document.querySelector("#page-title").textContent = activeItem.title;
  document.querySelector("#page-summary").textContent = activeItem.summary;
  document.querySelector("#status-title").textContent = `${activeItem.title} · ${state.engine.state}`;
  document.querySelector("#sidebar-status").textContent = state.engine.mode === "off" ? "Network Off" : state.engine.state;
  document.querySelector("#sidebar-status-dot").classList.toggle("on", state.engine.mode !== "off" && state.engine.state !== "Failed");
  document.querySelector("#proxy-state-value").textContent = state.engine.systemProxyActive ? "Active" : "Off";
  document.querySelector("#tunnel-state-value").textContent = state.engine.tunnelActive ? "Active" : "Off";
  document.querySelector("#runtime-value").textContent = state.lastRefreshAt ? formatTimestamp(state.lastRefreshAt) : "Not refreshed";
  const progress = document.querySelector("#traffic-progress");
  progress.classList.toggle("busy", Boolean(state.busyAction));
  progress.classList.toggle("active", !state.busyAction && state.engine.mode !== "off");
}

function render(state) {
  replaceChildren(document.querySelector("#nav"), renderNavigation(state));
  const content = [];
  if (state.fatalError) {
    content.push(node("div", { className: "error-banner", attributes: { role: "alert" } }, [
      node("strong", { text: "Operation failed" }),
      node("span", { text: state.fatalError }),
    ]));
  }
  content.push(renderPage(state));
  replaceChildren(document.querySelector("#page"), content);
  renderStatus(state);
}

function acceptBootPayload(payload) {
  if (!payload || typeof payload !== "object" || !payload.product || typeof payload.product !== "object") {
    throw new TypeError("Native boot payload is invalid");
  }
  store.update({
    product: {
      name: String(payload.product.name ?? "Clash for Mac").slice(0, 128),
      version: typeof payload.product.version === "string" ? payload.product.version.slice(0, 64) : null,
    },
  });
}

export async function reloadApplicationState() {
  if (store.get().busyAction) throw new Error("Another operation is already running");
  store.update({ busyAction: "reload", fatalError: null });
  const operations = [
    ["boot", async () => acceptBootPayload(await invoke("boot_payload"))],
    ["settings", loadSettings],
    ["engine", refreshEngineState],
  ];
  const results = await Promise.allSettled(operations.map(([, operation]) => operation()));
  const failures = [];
  results.forEach((result, index) => {
    if (result.status === "rejected") {
      const source = operations[index][0];
      failures.push(`${source}: ${errorMessage(result.reason)}`);
      logFailure(source, result.reason);
    }
  });
  if (!failures.length) {
    try {
      await loadProfiles();
    } catch (error) {
      failures.push(`profiles: ${errorMessage(error)}`);
      logFailure("profiles", error);
    }
  }
  store.update({
    busyAction: null,
    fatalError: failures.length ? failures.join(" · ") : null,
    lastRefreshAt: new Date().toISOString(),
  });

}

export async function bootstrap() {
  const disposeRender = store.subscribe(render);
  render(store.get());
  const disposeDomEvents = bindDomEvents({ reload: reloadApplicationState });
  let disposeNativeEvents = null;
  window.addEventListener("beforeunload", () => {
    disposeNativeEvents?.();
    disposeDomEvents();
    disposeRender();
  }, { once: true });
  try {
    disposeNativeEvents = await bindNativeEvents();
  } catch (error) {
    store.update({ fatalError: `Native event subscription failed: ${errorMessage(error)}` });
    logFailure("events", error);
  }
  await reloadApplicationState();
}
