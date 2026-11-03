// The Proxies, Rules and Logs pages: offline selection and latency tests, rule
// and provider metadata, and the log filter.
import assert from "node:assert/strict";
import test from "node:test";
import { t } from "../src/i18n.js";
import {
  OFF_ENGINE, RUNNING_ENGINE, appModule, deferred, dispatchDocumentEvent, element,
  invocationDetails, invoked, page, querySelectorAllElements, querySelectorElements, reloadButton,
  renderPage, responses, runtime, setEngine, state,
} from "./support/render-harness.mjs";

function savedToolbarPolicy() {
  return { profileId: "toolbar-profile", name: "Saved", groups: [
    { name: "GLOBAL", type: "Selector", now: "DIRECT", options: [{ name: "DIRECT", delay: null }] },
    { name: "PROXY", type: "Selector", now: "Node B", options: [
      { name: "Node A", delay: null }, { name: "Node B", delay: null },
    ] },
  ] };
}

test("offline locator reveals the saved selection even when filter and list hide it", async () => {
  const original = responses.engine_snapshot;
  try {
    await setEngine(OFF_ENGINE);
    state.savedProfilePolicy = savedToolbarPolicy();
    state.activeProxyGroup = null;
    state.proxyFilter = "does not match";
    state.toggles.showProxiesList = false;
    state.proxyGroupHideTimeouts.set("PROXY", true);
    state.savedProfilePolicy.groups[1].options[1].delayFailure = "timeout";
    let scrolled = false;
    querySelectorElements.set('[data-proxy-node="Node B"]', { scrollIntoView() { scrolled = true; } });
    await renderPage("proxies");
    await appModule.handleAction("scroll-to-selected-proxy");
    assert.equal(scrolled, false, "the card is scrolled to in the frame after it was rendered");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(scrolled, true);
    assert.equal(state.proxyFilter, "");
    assert.match(page.innerHTML, /cfw-node-card selected blink/u);
    assert.match(page.innerHTML, /<h2>PROXY<\/h2>/u);
    assert.doesNotMatch(page.innerHTML, /proxy-shield|◇/u);
  } finally {
    querySelectorElements.clear();
    state.proxyBlinkNode = null;
    state.proxyGroupHideTimeouts.clear();
    await setEngine(original);
  }
});

test("offline latency tests the displayed group and never enables network integration", async () => {
  const original = responses.engine_snapshot;
  const originalDelays = responses.test_proxy_delays;
  try {
    await setEngine(OFF_ENGINE);
    state.savedProfilePolicy = savedToolbarPolicy();
    state.activeProxyGroup = null;
    state.proxyFilter = "";
    responses.test_proxy_delays = [
      { name: "Node A", delay: 31, error_kind: null },
      { name: "Node B", delay: null, error_kind: "timeout" },
    ];
    await renderPage("proxies");
    invocationDetails.length = 0;
    await appModule.handleAction("delay-test");
    const calls = invocationDetails.filter(({ command }) => command === "test_proxy_delays");
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args.proxies, ["Node A", "Node B"]);
    assert.equal(calls[0].args.profileId, "toolbar-profile");
    assert.equal(invocationDetails.some(({ command }) => /start_system_proxy|start_tunnel|set_engine_mode/u.test(command)), false);
    assert.match(page.innerHTML, /31 ms/u);
    assert.match(page.innerHTML, /1 passed, 1 failed/u);
    await appModule.handleAction("toggle-hide-timed-out");
    assert.doesNotMatch(page.innerHTML, /data-proxy-node="Node B"/u);
    assert.match(page.innerHTML, /data-proxy-node="Node A"/u);
    assert.equal(state.proxyGroupHideTimeouts.has("GLOBAL"), false);
    await appModule.handleAction("toggle-hide-timed-out");
    assert.match(page.innerHTML, /data-proxy-node="Node B"/u);
  } finally {
    if (originalDelays === undefined) delete responses.test_proxy_delays;
    else responses.test_proxy_delays = originalDelays;
    state.proxyGroupHideTimeouts.clear();
    await setEngine(original);
  }
});

test("offline latency cancellation discards the in-flight reply and releases the toolbar", async () => {
  const original = responses.engine_snapshot;
  const originalDelays = responses.test_proxy_delays;
  const reply = deferred();
  let operation;
  try {
    await setEngine(OFF_ENGINE);
    state.savedProfilePolicy = savedToolbarPolicy();
    state.activeProxyGroup = "PROXY";
    responses.test_proxy_delays = reply.promise;
    await renderPage("proxies");
    operation = appModule.handleAction("delay-test");
    assert.equal(state.toggles.testingDelays, true);
    assert.doesNotMatch(page.innerHTML, /data-action="delay-test"[^>]*disabled/u);
    await appModule.handleAction("delay-test");
    assert.match(page.innerHTML, /Stopping latency test/u);
    reply.resolve([{ name: "Node A", delay: 99, error_kind: null }]);
    await operation;
    assert.equal(runtime.delayBatchInFlight, false);
    assert.equal(state.savedProfilePolicy.groups[1].options[0].delay, null);
    assert.doesNotMatch(page.innerHTML, /99 ms|data-action="delay-test"[^>]*disabled/u);
  } finally {
    reply.resolve([]);
    if (operation) await operation;
    if (originalDelays === undefined) delete responses.test_proxy_delays;
    else responses.test_proxy_delays = originalDelays;
    await setEngine(original);
  }
});

test("refreshing the same saved profile terminates the visible latency progress", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalProfiles = responses.profiles_snapshot;
  const originalText = responses.read_profile_text;
  const originalDelays = responses.test_proxy_delays;
  const reply = deferred();
  let operation;
  try {
    responses.profiles_snapshot = { profiles: [{ id: "toolbar-profile", name: "Saved", active: true, bytes: 200, source_kind: "local", updated_epoch_secs: 1 }], invalid_profiles: [] };
    responses.read_profile_text = { id: "toolbar-profile", name: "Saved", body: JSON.stringify({ outbounds: [
      { type: "socks5", tag: "Node A" }, { type: "socks5", tag: "Node B" },
      { type: "selector", tag: "PROXY", outbounds: ["Node A", "Node B"] },
    ] }) };
    await setEngine(OFF_ENGINE);
    await reloadButton.click();
    state.activeProxyGroup = "PROXY";
    responses.test_proxy_delays = reply.promise;
    await renderPage("proxies");
    operation = appModule.handleAction("delay-test");
    assert.equal(state.toggles.testingDelays, true);
    await reloadButton.click();
    reply.resolve([{ name: "Node A", delay: 99, error_kind: null }]);
    await operation;
    assert.equal(state.toggles.testingDelays, false);
    assert.doesNotMatch(page.innerHTML, /Testing latency…|Stopping latency test/u);
    assert.doesNotMatch(page.innerHTML, /99 ms/u);
  } finally {
    reply.resolve([]);
    if (operation) await operation;
    responses.profiles_snapshot = originalProfiles;
    responses.read_profile_text = originalText;
    if (originalDelays === undefined) delete responses.test_proxy_delays;
    else responses.test_proxy_delays = originalDelays;
    await setEngine(originalEngine);
  }
});

test("while the core is off, the nodes of a profile without a selector group can be chosen in the app selector", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalProfiles = responses.profiles_snapshot;
  const originalText = responses.read_profile_text;
  try {
    responses.profiles_snapshot = { profiles: [{ id: "nodes-profile", name: "Nodes", active: true, bytes: 200, source_kind: "local", updated_epoch_secs: 1 }], invalid_profiles: [] };
    responses.read_profile_text = { id: "nodes-profile", name: "Nodes", proxy_selections: { "cfw-proxy-selector": "Node B" },
      app_selector: { tag: "cfw-proxy-selector", members: ["Node A", "Node B"], default: "Node A" },
      body: JSON.stringify({ outbounds: [
        { type: "socks5", tag: "Node A" }, { type: "socks5", tag: "Node B" }, { type: "direct", tag: "DIRECT" },
      ] }) };
    await setEngine(OFF_ENGINE);
    await reloadButton.click();
    state.activeProxyGroup = "cfw-proxy-selector";
    const html = await renderPage("proxies");
    assert.match(html, /data-proxy-node="Node A" data-group="cfw-proxy-selector" data-node="Node A"/u);
    assert.match(html, /class="cfw-node-card selected[^"]*" data-proxy-node="Node B" data-group="cfw-proxy-selector"/u);
    assert.doesNotMatch(html, /Configured nodes/u);
  } finally {
    responses.profiles_snapshot = originalProfiles;
    responses.read_profile_text = originalText;
    await setEngine(originalEngine);
  }
});

test("log filter accessibility state follows delegated clicks without replacing the page or issuing IPC", async () => {
  const oldElement = globalThis.Element;
  const saved = { activePage: state.activePage, logFilter: state.logFilter, logSearch: state.logSearch, logs: state.logs, logsPaused: state.logsPaused };
  const selector = "[data-log-filter]";
  const oldButtons = querySelectorAllElements.get(selector);
  const oldStream = querySelectorElements.get(".log-stream");
  const oldHeading = querySelectorElements.get(".logs-layout .toolbar-panel h3");
  const stream = element("section");
  const heading = element("h3");
  class FilterElement {}
  const levels = ["all", "info", "debug", "warning", "error"];
  const buttons = levels.map((level) => {
    const attributes = new Map();
    const classes = new Set();
    return Object.assign(new FilterElement(), element("button"), {
      dataset: { logFilter: level },
      closest: (query) => query === selector ? buttons.find((button) => button.dataset.logFilter === level) : null,
      getAttribute: (name) => attributes.get(name) ?? null,
      setAttribute: (name, value) => attributes.set(name, String(value)),
      classList: {
        toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
        contains: (name) => classes.has(name),
      },
    });
  });
  function renderedFilters(html) {
    return [...html.matchAll(/<button\b[^>]*data-log-filter="([^"]+)"[^>]*>/gu)]
      .map(([tag, level]) => ({ level, pressed: tag.match(/aria-pressed="(true|false)"/u)?.[1] }));
  }
  try {
    globalThis.Element = FilterElement;
    Object.assign(state, { logFilter: "all", logSearch: "", logsPaused: false, logs: [
      { time: "10:00", level: "info", source: "test", message: "info evidence" },
      { time: "10:01", level: "error", source: "test", message: "error evidence" },
    ] });
    querySelectorAllElements.set(selector, buttons);
    querySelectorElements.set(".log-stream", stream);
    querySelectorElements.set(".logs-layout .toolbar-panel h3", heading);
    const html = await renderPage("logs");
    assert.deepEqual(renderedFilters(html), levels.map((level) => ({ level, pressed: String(level === "all") })));
    for (const { level, pressed } of renderedFilters(html)) {
      const button = buttons.find((value) => value.dataset.logFilter === level);
      button.setAttribute("aria-pressed", pressed);
      button.classList.toggle("selected", pressed === "true");
    }
    const ipcBefore = invoked.length;
    for (const level of ["warning", "error", "info", "debug", "all", "all", "info"]) {
      await dispatchDocumentEvent("click", { target: buttons.find((button) => button.dataset.logFilter === level) });
      assert.equal(state.logFilter, level);
      assert.deepEqual(buttons.map((button) => button.getAttribute("aria-pressed")), levels.map((value) => String(value === level)));
      assert.deepEqual(buttons.map((button) => button.classList.contains("selected")), levels.map((value) => value === level));
      assert.equal(page.innerHTML, html, "filtering must keep the existing page and its focusable controls");
      const visible = level === "all" ? 2 : ["info", "error"].includes(level) ? 1 : 0;
      assert.equal(heading.textContent, t("Log entries: {visible} / {total}", { visible, total: 2 }));
      for (const entry of ["info", "error"]) assert.equal(stream.innerHTML.includes(`${entry} evidence`), level === "all" || level === entry);
    }
    assert.equal(invoked.length, ipcBefore, "filter changes are local view state");
    await renderPage("general");
    assert.deepEqual(renderedFilters(await renderPage("logs")), levels.map((level) => ({ level, pressed: String(level === "info") })));
  } finally {
    Object.assign(state, saved);
    if (oldElement === undefined) delete globalThis.Element;
    else globalThis.Element = oldElement;
    for (const [map, key, value] of [
      [querySelectorAllElements, selector, oldButtons],
      [querySelectorElements, ".log-stream", oldStream],
      [querySelectorElements, ".logs-layout .toolbar-panel h3", oldHeading],
    ]) {
      if (value === undefined) map.delete(key);
      else map.set(key, value);
    }
    await renderPage(saved.activePage);
  }
});

test("missing rule metadata and unsupported providers render as unavailable", async () => {
  await setEngine(RUNNING_ENGINE);
  const providerCalls = invocationDetails.filter((entry) => entry.command === "providers_snapshot").length;
  await reloadButton.click();
  assert.equal(
    invocationDetails.filter((entry) => entry.command === "providers_snapshot").length,
    providerCalls,
    "a typed false capability must prevent provider probing",
  );
  state.rules = [{
    index: "unavailable",
    type: "Default",
    payload: "final",
    proxy: "route(proxy)",
    hits: "unavailable",
    size: "unavailable",
  }];
  const rules = await renderPage("rules");
  assert.equal((rules.match(/unavailable/gu) ?? []).length >= 2, true);

  const providers = await renderPage("providers");
  assert.ok(providers.includes("Proxy provider management unavailable"));
  assert.ok(providers.includes("Rule provider management unavailable"));
  assert.ok(providers.includes("unavailable in this application"));
});

test("the saved Rules view says when the mainland China direct rules follow the listed rules", async () => {
  await setEngine(OFF_ENGINE);
  const settings = state.runtimeSettings;
  try {
    for (const direct of [true, false]) {
      state.runtimeSettings = { ...settings, effective: { ...settings.effective, mainland_china_direct: direct } };
      const html = await renderPage("rules");
      assert.equal(html.includes("data-mainland-note"), direct, String(direct));
      if (direct) assert.ok(html.includes("rules apply in Rule mode after the listed rules, before the final route (MATCH)"));
    }
    // After a failed reload the last-read state is stale, so the note does
    // not claim the switch is on, as the General row does not.
    state.runtimeSettings = { ...settings, effective: { ...settings.effective, mainland_china_direct: true } };
    state.runtimeSettingsError = "Runtime settings response is invalid";
    assert.equal((await renderPage("rules")).includes("data-mainland-note"), false, "stale state after a failed reload");
    state.runtimeSettingsError = null;
    await setEngine(RUNNING_ENGINE);
    assert.equal((await renderPage("rules")).includes("data-mainland-note"), false, "live rules list the switch's own rules");
  } finally {
    state.runtimeSettingsError = null;
    state.runtimeSettings = settings;
  }
});
