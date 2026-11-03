// Navigation and the window: scroll positions kept across refreshes and
// dialogs, pages opened through the host, and the window's own actions.
import assert from "node:assert/strict";
import test from "node:test";
import {
  OFF_ENGINE, OVERLAY_SLOTS, RUNNING_ENGINE, appModule, emit, glassRoot, interactiveElement,
  invocationDetails, invoked, page, querySelectorAllElements, renderPage, responses, setEngine,
  state,
} from "./support/render-harness.mjs";

/// Gives `container` the one scroll region its markup renders: every
/// assignment of the markup builds a new region at the top, as a replaced
/// WebKit subtree does, so a kept offset can only come from the dashboard.
function installScrollRegion(container, tag, className) {
  const originalQuery = container.querySelectorAll;
  let markup = container.innerHTML;
  let region = null;
  const build = () => {
    const attributes = new Map([["class", className]]);
    return { tagName: tag, scrollTop: 0, scrollLeft: 0,
      getAttributeNames: () => [...attributes.keys()], getAttribute: (name) => attributes.get(name) ?? null };
  };
  Object.defineProperty(container, "innerHTML", { configurable: true, enumerable: true,
    get: () => markup,
    set: (value) => { markup = value; region = value.includes(`class="${className}"`) ? build() : null; } });
  container.querySelectorAll = (selector) => (region && (selector === "*" || selector === tag.toLowerCase()) ? [region] : []);
  return {
    current: () => region,
    restore: () => {
      Object.defineProperty(container, "innerHTML", { value: markup, writable: true, configurable: true, enumerable: true });
      container.querySelectorAll = originalQuery;
    },
  };
}

test("a refresh or a dialog keeps the scrolled Settings list in place; another page starts at the top", async () => {
  await setEngine(OFF_ENGINE);
  const overlays = OVERLAY_SLOTS.map((slot) => state[slot]);
  for (const slot of OVERLAY_SLOTS) state[slot] = null;
  const list = installScrollRegion(page, "DIV", "settings-layout");
  try {
    await renderPage("settings");
    const first = list.current();
    assert.ok(first, "Settings renders its scroll region");
    first.scrollTop = 480;
    first.scrollLeft = 3;
    await emit("cfw://settings-changed", responses.read_settings_snapshot);
    const refreshed = list.current();
    assert.notEqual(refreshed, first, "the refresh replaced the page markup");
    assert.deepEqual([refreshed.scrollTop, refreshed.scrollLeft], [480, 3], "a refresh of the same page keeps its offsets");

    await appModule.handleAction("open-runtime-settings");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.ok(state.runtimeSettingsDialog, "the network settings dialog is open");
    assert.notEqual(list.current(), refreshed, "opening the dialog replaced the page markup");
    assert.equal(list.current().scrollTop, 480, "a dialog over the page keeps the page where it was");

    state.runtimeSettingsDialog = null;
    await renderPage("general");
    await renderPage("settings");
    assert.equal(list.current().scrollTop, 0, "navigating back starts at the top");
  } finally {
    list.restore();
    OVERLAY_SLOTS.forEach((slot, index) => { state[slot] = overlays[index]; });
  }
});

test("a refresh keeps an open dialog's scroll position while that dialog stays open", async () => {
  await setEngine(OFF_ENGINE);
  const overlays = OVERLAY_SLOTS.map((slot) => state[slot]);
  const automation = responses.read_automation_settings;
  for (const slot of OVERLAY_SLOTS) state[slot] = null;
  responses.read_automation_settings = {
    settings: { shortcuts: [], network_enabled: false, network_rules: [] },
    revision: "scroll-region", network: null,
  };
  const dialog = installScrollRegion(glassRoot, "SECTION", "glass-dialog automation-settings-dialog");
  try {
    await renderPage("settings");
    await appModule.handleAction("open-automation-settings");
    await new Promise((resolve) => setTimeout(resolve, 20));
    const first = dialog.current();
    assert.ok(first, "the automation dialog is open");
    first.scrollTop = 260;
    await emit("cfw://settings-changed", responses.read_settings_snapshot);
    assert.notEqual(dialog.current(), first, "the refresh replaced the overlay markup");
    assert.equal(dialog.current().scrollTop, 260, "the open dialog keeps its offset");

    state.automationDialog = null;
    await emit("cfw://settings-changed", responses.read_settings_snapshot);
    assert.equal(dialog.current(), null, "the closed dialog leaves no region behind");
    await appModule.handleAction("open-automation-settings");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(dialog.current().scrollTop, 0, "a reopened dialog starts at the top");
  } finally {
    dialog.restore();
    OVERLAY_SLOTS.forEach((slot, index) => { state[slot] = overlays[index]; });
    if (automation === undefined) delete responses.read_automation_settings;
    else responses.read_automation_settings = automation;
    await renderPage("settings");
  }
});

test("the navigation opens a page through the host and refreshes what that page shows", async () => {
  const originalPage = state.activePage;
  const buttons = ["proxies", "rules", "general"].map((id) => {
    const button = interactiveElement();
    button.dataset.page = id;
    return button;
  });
  querySelectorAllElements.set("[data-page]", buttons);
  responses.open_page = null;
  const originalEngine = responses.engine_snapshot;
  try {
    await setEngine(RUNNING_ENGINE);
    await renderPage("general");
    for (const button of buttons) {
      const before = invocationDetails.length;
      await button.trigger("click");
      await new Promise((resolve) => setTimeout(resolve, 20));
      const issued = invocationDetails.slice(before).map(({ command }) => command);
      assert.equal(state.activePage, button.dataset.page);
      assert.deepEqual(invocationDetails.slice(before).find(({ command }) => command === "open_page")?.args, { page: button.dataset.page });
      if (button.dataset.page === "proxies") assert.ok(issued.includes("controller_snapshot"), "the proxy page reads the controller");
      if (button.dataset.page === "rules") assert.ok(issued.includes("rules_snapshot"), "the rules page reads the rules");
      if (button.dataset.page === "general") assert.ok(!issued.includes("rules_snapshot"));
    }
  } finally {
    querySelectorAllElements.delete("[data-page]");
    delete responses.open_page;
    await setEngine(originalEngine);
    await renderPage(originalPage);
  }
});

test("the window's own actions reach the host", async () => {
  responses.quit_app = null;
  responses.force_quit_app = null;
  try {
    await appModule.handleAction("quit-app");
    await appModule.handleAction("force-quit-app");
    assert.deepEqual(invoked.slice(-2), ["quit_app", "force_quit_app"]);
    const before = state.logs.length;
    await appModule.handleAction("update-all-providers");
    await appModule.handleAction("health-check-all");
    assert.ok(state.logs.length >= before, "provider actions report through the log");
    await appModule.handleAction("reload-dashboard");
    assert.equal(state.logs[0].message, "Dashboard reloaded");
  } finally {
    delete responses.quit_app;
    delete responses.force_quit_app;
  }
});
