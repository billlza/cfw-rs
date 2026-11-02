import { dom, element, host, settle, spy } from "./support/fake-host.mjs";
import { replaceEngineIdentity, runEngine, stopEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state } from "../src/state.js";
import { createProxyActions } from "../src/proxy-actions.js";

const lastLog = () => state.logs[0];

function deps(overrides = {}) {
  return {
    renderPage: spy(),
    activeProxyGroup: () => ({ name: "Proxy", now: "HK" }),
    hideTimedOutProxies: () => false,
    revealSelectedProxy: spy(),
    runProxyDelayTest: spy(async () => undefined),
    changeProxyPage: spy(),
    slugDomId: (name) => name.toLowerCase(),
    cancelDelayTest: spy(),
    applyProxyMode: spy(async () => true),
    applyProxySelection: spy(async () => true),
    ...overrides,
  };
}

beforeEach(() => {
  host.reset();
  dom.reset();
  state.logs = [];
  state.activePage = "proxies";
  state.connections = [{ id: "a" }];
  state.proxyFilter = "hk";
  state.proxyBlinkNode = null;
  state.proxyGroupHideTimeouts.clear();
  state.collapsedProxyGroups.clear();
  state.toggles.showProxiesList = false;
  state.toggles.showProxyFilter = true;
  state.toggles.hideUnavailable = false;
  stopEngine();
});

test("scrolling to the selected proxy reveals it, then stops its highlight", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const d = deps();
  const card = dom.set("[data-proxy-node=\"HK\"]", element("article"));
  await createProxyActions(d).actions["scroll-to-selected-proxy"]();
  assert.equal(state.toggles.showProxiesList, true);
  assert.equal(state.proxyFilter, "");
  assert.equal(state.proxyGroupHideTimeouts.get("Proxy"), false);
  assert.equal(state.proxyBlinkNode, "HK");
  assert.deepEqual(d.revealSelectedProxy.calls, [["HK"]]);
  await settle();
  assert.deepEqual(card.scrolledIntoView, [{ block: "center", behavior: "smooth" }]);
  const renders = d.renderPage.count();
  t.mock.timers.tick(1200);
  assert.equal(state.proxyBlinkNode, null);
  assert.equal(d.renderPage.count(), renders + 1);
});

test("a highlight replaced or off-page is not rendered again", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const d = deps();
  await createProxyActions(d).actions["scroll-to-selected-proxy"]();
  state.proxyBlinkNode = "JP";
  t.mock.timers.tick(1200);
  assert.equal(state.proxyBlinkNode, "JP");
  await createProxyActions(d).actions["scroll-to-selected-proxy"]();
  state.activePage = "general";
  const renders = d.renderPage.count();
  t.mock.timers.tick(1200);
  assert.equal(state.proxyBlinkNode, null);
  assert.equal(d.renderPage.count(), renders, "the Proxies page is not shown, nothing to render");
});

test("without a selected proxy there is nothing to scroll to", async () => {
  const d = deps({ activeProxyGroup: () => null });
  await createProxyActions(d).actions["scroll-to-selected-proxy"]();
  assert.equal(lastLog().message, "No selected proxy to scroll to");
  assert.equal(d.renderPage.count(), 0);
});

test("the list toggles hide timeouts per group, unavailable nodes, the list and the filter", async () => {
  const d = deps({ hideTimedOutProxies: () => true });
  const { actions } = createProxyActions(d);
  await actions["toggle-hide-timed-out"]();
  assert.equal(state.proxyGroupHideTimeouts.get("Proxy"), false);
  await createProxyActions(deps({ activeProxyGroup: () => null })).actions["toggle-hide-timed-out"]();
  assert.equal(state.proxyGroupHideTimeouts.size, 1, "no group, no change");
  await actions["toggle-hide-unavailable"]();
  assert.equal(state.toggles.hideUnavailable, true);
  assert.equal(state.proxyGroupHideTimeouts.size, 0);
  await actions["toggle-show-proxies"]();
  assert.equal(state.toggles.showProxiesList, true);
  await actions["toggle-show-proxies"]();
  assert.equal(state.toggles.showProxiesList, false);
  await actions["toggle-proxy-filter"]();
  assert.equal(state.toggles.showProxyFilter, false);
  assert.equal(state.proxyFilter, "", "hiding the filter clears it");
  state.proxyFilter = "keep";
  await actions["toggle-proxy-filter"]();
  assert.equal(state.proxyFilter, "keep");
  assert.equal(d.renderPage.count(), 6);
});

test("breaking proxy connections needs a running engine and reports both outcomes", async () => {
  const d = deps();
  const { actions } = createProxyActions(d);
  await actions["break-proxy-connections"]();
  assert.equal(lastLog().message, "Breaking proxy connections is unavailable while the engine is Off");
  runEngine();
  host.respond("close_all_connections", null);
  host.respond("controller_snapshot", null);
  await actions["break-proxy-connections"]();
  assert.ok(state.logs.some((entry) => entry.message === "Broke 1 connection(s)"));
  host.respond("close_all_connections", new Error("busy"));
  await actions["break-proxy-connections"]();
  assert.equal(lastLog().message, "Break connections failed: busy");
  const renders = d.renderPage.count();
  host.respond("close_all_connections", () => { replaceEngineIdentity(); return null; });
  await actions["break-proxy-connections"]();
  runEngine();
  host.respond("close_all_connections", () => { replaceEngineIdentity(); return new Error("late"); });
  await actions["break-proxy-connections"]();
  assert.equal(d.renderPage.count(), renders, "an answer for an earlier engine renders nothing");
});

test("a delay test runs and a reload reports whether the controller answered", async () => {
  const d = deps();
  const { actions } = createProxyActions(d);
  await actions["delay-test"]();
  assert.equal(d.runProxyDelayTest.count(), 1);
  await actions["reload-proxies"]();
  assert.equal(lastLog().message, "Reloading proxies is unavailable while the engine is Off");
  runEngine();
  host.respond("controller_snapshot", { config: { mode: "rule" }, proxies: { groups: [] } });
  host.respond("refresh_tray_menu", null);
  await actions["reload-proxies"]();
  assert.equal(lastLog().message, "Controller snapshot reloaded");
  host.respond("controller_snapshot", new Error("down"));
  await actions["reload-proxies"]();
  assert.equal(lastLog().message, "Controller unavailable; keeping local data");
});

test("the Proxies page binds paging, filtering, groups, modes and node selection", async () => {
  const d = deps();
  const page = element("button", { dataset: { proxyPage: "1" } });
  dom.setAll("[data-proxy-page]", [page]);
  const filter = dom.set("[data-proxy-filter]", element("input"));
  const collapse = element("button", { dataset: { collapseGroup: "Proxy" } });
  dom.setAll("[data-collapse-group]", [collapse]);
  const scroll = element("button", { dataset: { scrollGroup: "Proxy" } });
  dom.setAll("[data-scroll-group]", [scroll]);
  const groupSection = dom.byId("proxy-group-proxy", element("section"));
  const tab = element("button", { dataset: { proxyGroupTab: "Auto" } });
  dom.setAll("[data-proxy-group-tab]", [tab]);
  const mode = element("button", { dataset: { mode: "Global" } });
  dom.setAll("[data-mode]", [mode]);
  const node = element("button", { dataset: { group: "Proxy", node: "JP" } });
  dom.setAll("[data-group][data-node]", [node]);
  createProxyActions(d).bindPage();

  await page.fire("click");
  assert.deepEqual(d.changeProxyPage.calls, [[1]]);
  await filter.fire("input", { currentTarget: { value: "jp" } });
  assert.equal(state.proxyFilter, "jp");
  await collapse.fire("click");
  assert.equal(state.collapsedProxyGroups.has("Proxy"), true);
  await collapse.fire("click");
  assert.equal(state.collapsedProxyGroups.has("Proxy"), false);
  await scroll.fire("click");
  assert.deepEqual(groupSection.scrolledIntoView, [{ block: "start", behavior: "smooth" }]);
  await tab.fire("click");
  assert.equal(d.cancelDelayTest.count(), 1);
  assert.equal(state.activeProxyGroup, "Auto");
  await mode.fire("click");
  assert.deepEqual(d.applyProxyMode.calls, [["Global"]]);
  await node.fire("click");
  assert.deepEqual(d.applyProxySelection.calls, [["Proxy", "JP"]]);
  assert.equal(d.renderPage.count(), 7);

  dom.reset();
  createProxyActions(d).bindPage();
  await scroll.fire("click");
  assert.equal(groupSection.scrolledIntoView.length, 1, "a group that is not rendered is not scrolled to");
});
