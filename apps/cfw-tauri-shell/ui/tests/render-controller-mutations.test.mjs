// Proxy mode and selector changes through the controller: Direct mode,
// single-flight mutations, and responses from an older engine generation.
import assert from "node:assert/strict";
import test from "node:test";
import {
  RUNNING_ENGINE, controllerSnapshotWith, deferred, emit, interactiveElement, invocationDetails,
  querySelectorAllElements, reloadButton, renderPage, responses, runtime, setEngine, state,
  waitForInvocation,
} from "./support/render-harness.mjs";

test("a fresh zero-group snapshot still exposes the active Direct mode", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  try {
    const direct = controllerSnapshotWith({ mode: "direct" });
    direct.proxies = { groups: [], proxies: [] };
    responses.controller_snapshot = direct;
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();

    const html = await renderPage("proxies");
    const button = html.match(/<button class="selected" data-mode="Direct"([^>]*)>/u);
    assert.ok(button, "Direct must remain visible for a valid profile with zero proxy groups");
    assert.doesNotMatch(button[1], /disabled/u);
    assert.match(html, /Active profile has no proxy groups/u);
  } finally {
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("controller loss clears Direct state until the same engine publishes a fresh snapshot", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const directMode = interactiveElement();
  directMode.dataset.mode = "Direct";
  try {
    const direct = controllerSnapshotWith({ mode: "direct" });
    responses.controller_snapshot = direct;
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();

    responses.controller_snapshot = null;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    assert.equal(state.controllerStatus, "controller offline");
    assert.equal(state.mode, null);
    assert.deepEqual(state.proxyGroups, []);

    querySelectorAllElements.set("[data-mode]", [directMode]);
    const offlineHtml = await renderPage("proxies");
    assert.match(offlineHtml, /data-mode="Direct"[^>]*disabled/u);
    const mutationsBefore = invocationDetails.filter(
      (entry) => entry.command === "set_proxy_mode",
    ).length;
    await directMode.trigger("click");
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "set_proxy_mode").length,
      mutationsBefore,
    );

    responses.controller_snapshot = direct;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    assert.equal(state.controllerStatus, "controller live");
    assert.equal(state.mode, "Direct");
    const recoveredHtml = await renderPage("proxies");
    const recovered = recoveredHtml.match(/<button class="selected" data-mode="Direct"([^>]*)>/u);
    assert.ok(recovered, "Direct must return only after a fresh controller readback");
    assert.doesNotMatch(recovered[1], /disabled/u);
  } finally {
    querySelectorAllElements.clear();
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("Direct fallback state is rendered read-only and cannot select a proxy", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const selection = interactiveElement();
  selection.dataset.group = "GLOBAL";
  selection.dataset.node = "direct";
  try {
    const direct = controllerSnapshotWith({ mode: "direct" });
    direct.proxies = {
      groups: [{ name: "GLOBAL", kind: "Fallback", now: "direct", options: [], history: [] }],
      proxies: [{ name: "direct", kind: "Direct", udp: true, history: [] }],
    };
    responses.controller_snapshot = direct;
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    querySelectorAllElements.set("[data-group][data-node]", [selection]);

    const html = await renderPage("proxies");
    assert.match(html, /data-proxy-node="direct"[^>]*disabled/u);
    assert.match(html, /• direct/u);
    const before = invocationDetails.filter((entry) => entry.command === "select_proxy").length;
    await selection.trigger("click");
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "select_proxy").length,
      before,
      "a read-only Direct observation must never become select_proxy IPC",
    );
  } finally {
    querySelectorAllElements.clear();
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("proxy mode mutations are single-flight and an old failure cannot roll back the latest success", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const originalMutation = responses.set_proxy_mode;
  const hadMutation = Object.hasOwn(responses, "set_proxy_mode");
  const originalBreakOnChange = state.toggles.breakOnProxyChange;
  const first = deferred();
  const second = deferred();
  const actions = [];
  let mutationCall = 0;

  try {
    responses.controller_snapshot = controllerSnapshotWith({ mode: "rule" });
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    state.toggles.breakOnProxyChange = false;

    const globalMode = interactiveElement();
    globalMode.dataset.mode = "Global";
    const directMode = interactiveElement();
    directMode.dataset.mode = "Direct";
    querySelectorAllElements.set("[data-mode]", [globalMode, directMode]);
    await renderPage("proxies");

    responses.set_proxy_mode = () => {
      const result = [first.promise, second.promise][mutationCall];
      mutationCall += 1;
      assert.ok(result, "only the two requested mode mutations may reach native IPC");
      return result;
    };
    responses.controller_snapshot = controllerSnapshotWith({ mode: "direct" });
    const mutationCalls = invocationDetails.filter((entry) => entry.command === "set_proxy_mode").length;
    const snapshotCalls = invocationDetails.filter((entry) => entry.command === "controller_snapshot").length;

    actions.push(globalMode.trigger("click"));
    await waitForInvocation("set_proxy_mode", mutationCalls);
    actions.push(directMode.trigger("click"));
    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.equal(
      invocationDetails.filter((entry) => entry.command === "set_proxy_mode").length,
      mutationCalls + 1,
      "the second mode intent must wait for the first native mutation",
    );
    assert.equal(state.mode, "Direct", "the latest intent is rendered while its native write is queued");

    first.reject(new Error("old-mode-failure-marker"));
    await waitForInvocation("set_proxy_mode", mutationCalls + 1);
    second.resolve(null);
    await Promise.all(actions);

    const calls = invocationDetails
      .filter((entry) => entry.command === "set_proxy_mode")
      .slice(mutationCalls);
    assert.deepEqual(calls.map((entry) => entry.args.mode), ["Global", "Direct"]);
    assert.equal(state.mode, "Direct");
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "controller_snapshot").length,
      snapshotCalls + 1,
      "only the latest mode intent publishes one authoritative controller readback",
    );
    assert.equal(state.logs.some((entry) => entry.message.includes("old-mode-failure-marker")), false);
    assert.ok(state.logs.some((entry) => entry.message === "Proxy mode switched to Direct"));
  } finally {
    first.resolve(null);
    second.resolve(null);
    await Promise.allSettled(actions);
    querySelectorAllElements.clear();
    state.toggles.breakOnProxyChange = originalBreakOnChange;
    if (hadMutation) responses.set_proxy_mode = originalMutation;
    else delete responses.set_proxy_mode;
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("mode and selector mutations share one lane without readback rollback", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const originalModeMutation = responses.set_proxy_mode;
  const originalSelectorMutation = responses.select_proxy;
  const hadModeMutation = Object.hasOwn(responses, "set_proxy_mode");
  const hadSelectorMutation = Object.hasOwn(responses, "select_proxy");
  const originalBreakOnChange = state.toggles.breakOnProxyChange;
  const originalLogs = [...state.logs];
  const modePending = deferred();
  const selectorPending = deferred();
  const actions = [];
  let readbackCall = 0;

  try {
    responses.controller_snapshot = controllerSnapshotWith({ mode: "rule", selected: "HK" });
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    state.toggles.breakOnProxyChange = false;

    const globalMode = interactiveElement();
    globalMode.dataset.mode = "Global";
    const jp = interactiveElement();
    jp.dataset.group = "Proxy";
    jp.dataset.node = "JP";
    querySelectorAllElements.set("[data-mode]", [globalMode]);
    querySelectorAllElements.set("[data-group][data-node]", [jp]);
    await renderPage("proxies");

    responses.set_proxy_mode = modePending.promise;
    responses.select_proxy = selectorPending.promise;
    const modeReadback = controllerSnapshotWith({ mode: "global", selected: "HK" });
    const selectorReadback = controllerSnapshotWith({ mode: "global", selected: "JP" });
    responses.controller_snapshot = () => {
      const snapshot = [modeReadback, selectorReadback][readbackCall];
      readbackCall += 1;
      assert.ok(snapshot, "the mixed mutation lane performs exactly two readbacks");
      return structuredClone(snapshot);
    };
    const modeCalls = invocationDetails.filter(({ command }) => command === "set_proxy_mode").length;
    const selectorCalls = invocationDetails.filter(({ command }) => command === "select_proxy").length;

    actions.push(globalMode.trigger("click"));
    await waitForInvocation("set_proxy_mode", modeCalls);
    actions.push(jp.trigger("click"));
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(state.mode, "Global");
    assert.equal(state.proxyGroups.find(({ name }) => name === "Proxy")?.now, "JP");
    assert.equal(
      invocationDetails.filter(({ command }) => command === "select_proxy").length,
      selectorCalls,
      "selector IPC must wait while the earlier mode mutation is pending",
    );

    modePending.resolve(null);
    await waitForInvocation("select_proxy", selectorCalls);
    assert.equal(state.mode, "Global");
    assert.equal(
      state.proxyGroups.find(({ name }) => name === "Proxy")?.now,
      "JP",
      "mode readback must reapply the queued selector intent",
    );

    selectorPending.resolve(null);
    await Promise.all(actions);
    assert.equal(readbackCall, 2);
    assert.equal(state.mode, "Global");
    assert.equal(state.proxyGroups.find(({ name }) => name === "Proxy")?.now, "JP");
  } finally {
    modePending.resolve(null);
    selectorPending.resolve(null);
    await Promise.allSettled(actions);
    querySelectorAllElements.clear();
    state.toggles.breakOnProxyChange = originalBreakOnChange;
    if (hadModeMutation) responses.set_proxy_mode = originalModeMutation;
    else delete responses.set_proxy_mode;
    if (hadSelectorMutation) responses.select_proxy = originalSelectorMutation;
    else delete responses.select_proxy;
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
    state.logs = originalLogs;
  }
});

test("a controller mutation response from an older engine generation performs zero UI writeback", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const originalMutation = responses.set_proxy_mode;
  const hadMutation = Object.hasOwn(responses, "set_proxy_mode");
  const originalBreakOnChange = state.toggles.breakOnProxyChange;
  const pending = deferred();
  let action = null;
  const nextEngine = {
    ...RUNNING_ENGINE,
    snapshot: {
      ...RUNNING_ENGINE.snapshot,
      generation: 4,
      config_digest: "digest-4",
      state: {
        state: "proxy_active",
        runtime: {
          ...RUNNING_ENGINE.snapshot.state.runtime,
          context: {
            ...RUNNING_ENGINE.snapshot.state.runtime.context,
            generation: 4,
          },
          config_digest: "digest-4",
        },
      },
    },
  };

  try {
    responses.controller_snapshot = controllerSnapshotWith({ mode: "rule" });
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    state.toggles.breakOnProxyChange = false;

    const globalMode = interactiveElement();
    globalMode.dataset.mode = "Global";
    querySelectorAllElements.set("[data-mode]", [globalMode]);
    await renderPage("proxies");
    responses.set_proxy_mode = pending.promise;
    const mutationCalls = invocationDetails.filter((entry) => entry.command === "set_proxy_mode").length;
    const snapshotCalls = invocationDetails.filter((entry) => entry.command === "controller_snapshot").length;

    action = globalMode.trigger("click");
    await waitForInvocation("set_proxy_mode", mutationCalls);
    assert.equal(state.mode, "Global");

    await setEngine(nextEngine);
    assert.equal(state.mode, null, "a new engine identity immediately discards the old optimistic mode");
    pending.resolve(null);
    await action;

    assert.equal(state.mode, null);
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "controller_snapshot").length,
      snapshotCalls,
      "the stale mutation response must not schedule controller readback on the new generation",
    );
    assert.equal(state.logs.some((entry) => entry.message === "Proxy mode switched to Global"), false);
  } finally {
    pending.resolve(null);
    if (action) await action.catch(() => {});
    querySelectorAllElements.clear();
    state.toggles.breakOnProxyChange = originalBreakOnChange;
    if (hadMutation) responses.set_proxy_mode = originalMutation;
    else delete responses.set_proxy_mode;
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("proxy selector mutations are single-flight and a failed latest intent publishes controller readback", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const originalMutation = responses.select_proxy;
  const hadMutation = Object.hasOwn(responses, "select_proxy");
  const originalBreakOnChange = state.toggles.breakOnProxyChange;
  const first = deferred();
  const second = deferred();
  const actions = [];
  let mutationCall = 0;

  try {
    responses.controller_snapshot = controllerSnapshotWith({ selected: "HK", extraOptions: ["SG"] });
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    state.toggles.breakOnProxyChange = false;

    const jp = interactiveElement();
    jp.dataset.group = "Proxy";
    jp.dataset.node = "JP";
    const sg = interactiveElement();
    sg.dataset.group = "Proxy";
    sg.dataset.node = "SG";
    querySelectorAllElements.set("[data-group][data-node]", [jp, sg]);
    await renderPage("proxies");

    responses.select_proxy = () => {
      const result = [first.promise, second.promise][mutationCall];
      mutationCall += 1;
      assert.ok(result, "only the two requested selector mutations may reach native IPC");
      return result;
    };
    responses.controller_snapshot = controllerSnapshotWith({ selected: "JP" });
    const mutationCalls = invocationDetails.filter((entry) => entry.command === "select_proxy").length;
    const snapshotCalls = invocationDetails.filter((entry) => entry.command === "controller_snapshot").length;

    actions.push(jp.trigger("click"));
    await waitForInvocation("select_proxy", mutationCalls);
    actions.push(sg.trigger("click"));
    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.equal(
      invocationDetails.filter((entry) => entry.command === "select_proxy").length,
      mutationCalls + 1,
      "the second selector intent must wait for the first native mutation",
    );
    assert.equal(state.proxyGroups.find((group) => group.name === "Proxy")?.now, "SG");

    first.resolve(null);
    await waitForInvocation("select_proxy", mutationCalls + 1);
    second.reject(new Error("latest-selector-failure-marker"));
    await Promise.all(actions);

    const calls = invocationDetails
      .filter((entry) => entry.command === "select_proxy")
      .slice(mutationCalls);
    assert.deepEqual(calls.map((entry) => entry.args.proxy), ["JP", "SG"]);
    assert.equal(
      state.proxyGroups.find((group) => group.name === "Proxy")?.now,
      "JP",
      "a failed latest selector intent must show authoritative controller state",
    );
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "controller_snapshot").length,
      snapshotCalls + 1,
    );
    assert.ok(state.logs.some((entry) => (
      entry.message.includes("latest-selector-failure-marker")
      && entry.message.includes("controller readback reports JP")
    )));
    assert.equal(state.logs.some((entry) => entry.message === "Proxy group Proxy switched to JP"), false);
  } finally {
    first.resolve(null);
    second.resolve(null);
    await Promise.allSettled(actions);
    querySelectorAllElements.clear();
    state.toggles.breakOnProxyChange = originalBreakOnChange;
    if (hadMutation) responses.select_proxy = originalMutation;
    else delete responses.select_proxy;
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});
