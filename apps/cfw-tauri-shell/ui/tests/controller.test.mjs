import { dom, host, settle, spy } from "./support/fake-host.mjs";
import { replaceEngineIdentity, runEngine, stopEngine, streamBinding } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state, runtime } from "../src/state.js";
import {
  closeConnectionsAfterProxyChange,
  loadControllerSnapshot,
  loadControllerSnapshotWithRetry,
  loadRulesSnapshot,
} from "../src/controller-reads.js";
import { applyConnectionsSnapshot, applyControllerSnapshot, clearControllerBackedState } from "../src/controller-snapshot.js";
import { captureEngineIdentityToken } from "../src/engine-identity.js";
import { createControllerMutations } from "../src/controller-mutations.js";
import { createProxyCommands } from "../src/proxy-commands.js";
import { setConnectionsStreamRunning, startLiveStreams } from "../src/live-streams.js";

const lastLog = () => state.logs[0];
const messages = () => state.logs.map((entry) => entry.message);

function snapshot({ mode = "rule", selected = "HK", options = ["HK", "JP"], kind = "Selector", connections } = {}) {
  return {
    config: { mode, "log-level": "info" },
    proxies: {
      proxies: [
        { name: "HK", type: "Shadowsocks", udp: true, history: [{ delay: 80 }] },
        { name: "JP", kind: "Trojan", history: [] },
      ],
      groups: [{ name: "Proxy", kind, now: selected, options }],
    },
    connections,
  };
}

beforeEach(() => {
  host.reset();
  dom.reset();
  state.logs = [];
  state.mode = null;
  state.proxyGroups = [];
  state.connections = [];
  state.rules = [];
  state.toggles.testingDelays = false;
  state.toggles.breakOnProxyChange = false;
  state.proxyDelayResults.clear();
  state.savedProfilePolicy = null;
  state.savedProxySelectionBusy = false;
  state.controllerStatus = null;
  state.connectionStream = { at: 0, uploadTotal: 0, downloadTotal: 0, rows: new Map() };
  state.traffic.upload = 0;
  state.traffic.download = 0;
  runtime.controllerMutationLatestByLane.clear();
  runtime.controllerMutationPendingByLane.clear();
  runtime.controllerMutationQueue.length = 0;
  for (const lane of [runtime.connectionsLiveStream, runtime.logLiveStream]) {
    lane.binding = null;
    lane.desiredRunning = false;
    lane.operation = Promise.resolve();
  }
  stopEngine();
});

test("a controller read needs the engine identity it started with", async () => {
  state.proxyGroups = [{ name: "stale", options: [] }];
  assert.equal(await loadControllerSnapshot(), false);
  assert.deepEqual(state.proxyGroups, [], "an Off engine leaves no controller state");
  assert.equal(state.controllerStatus, "engine off");
  runEngine();
  assert.equal(await loadControllerSnapshot(true, captureEngineIdentityToken(), () => false), false);
  assert.deepEqual(host.commands(), [], "a refused publication reads nothing");
});

test("a controller snapshot is applied, observed and followed by a tray refresh", async () => {
  runEngine();
  const observed = [];
  host.respond("controller_snapshot", snapshot());
  host.respond("refresh_tray_menu", null);
  assert.equal(await loadControllerSnapshot(true, captureEngineIdentityToken(), () => true, (value) => observed.push(value)), true);
  assert.equal(state.mode, "Rule");
  assert.equal(state.proxyGroups[0].now, "HK");
  assert.equal(observed.length, 1);
  await settle();
  assert.deepEqual(host.commands(), ["controller_snapshot", "refresh_tray_menu"]);
});

test("a missing or refused snapshot clears controller state and is reported only when asked", async () => {
  runEngine();
  state.proxyGroups = [{ name: "stale", options: [] }];
  host.respond("controller_snapshot", null);
  assert.equal(await loadControllerSnapshot(false), false);
  assert.equal(state.controllerStatus, "controller offline");
  assert.deepEqual(state.proxyGroups, []);
  assert.equal(state.logs.length, 0);
  assert.equal(await loadControllerSnapshot(true), false);
  assert.equal(lastLog().message, "Running engine returned no controller snapshot");
  host.respond("controller_snapshot", new Error("connection refused"));
  assert.equal(await loadControllerSnapshot(false), false);
  assert.equal(state.logs.length, 1);
  assert.equal(await loadControllerSnapshot(true), false);
  assert.equal(lastLog().message, "connection refused");
});

test("a controller answer that arrives after the engine changed is dropped", async () => {
  runEngine();
  host.respond("controller_snapshot", () => { replaceEngineIdentity(); return snapshot(); });
  assert.equal(await loadControllerSnapshot(), false);
  assert.deepEqual(state.proxyGroups, []);
  runEngine();
  host.respond("controller_snapshot", () => { replaceEngineIdentity(); return new Error("late"); });
  assert.equal(await loadControllerSnapshot(), false);
  assert.equal(state.logs.length, 0);
});

test("a failed tray refresh is reported while its engine is still current", async () => {
  runEngine();
  host.respond("controller_snapshot", snapshot());
  host.respond("refresh_tray_menu", new Error("tray gone"));
  await loadControllerSnapshot();
  await settle();
  assert.equal(lastLog().message, "Tray refresh failed: tray gone");
  host.respond("refresh_tray_menu", () => { replaceEngineIdentity(); return new Error("tray gone"); });
  state.logs = [];
  runEngine();
  await loadControllerSnapshot();
  await settle();
  assert.equal(state.logs.length, 0);
});

test("a retried controller read stops at the first success and reports only the last failure", async () => {
  assert.equal(await loadControllerSnapshotWithRetry(3, 0), false);
  runEngine();
  let attempts = 0;
  host.respond("controller_snapshot", () => (++attempts < 3 ? null : snapshot()));
  host.respond("refresh_tray_menu", null);
  assert.equal(await loadControllerSnapshotWithRetry(3, 0), true);
  assert.equal(attempts, 3);
  assert.equal(state.logs.length, 0, "earlier failures are not reported");
  host.respond("controller_snapshot", null);
  assert.equal(await loadControllerSnapshotWithRetry(2, 0), false);
  assert.deepEqual(messages(), ["Running engine returned no controller snapshot"]);
  host.respond("controller_snapshot", () => { replaceEngineIdentity(); return null; });
  runEngine();
  assert.equal(await loadControllerSnapshotWithRetry(3, 0), false, "an engine change ends the retries");
});

test("rules are read from the running engine and cleared when it stops", async () => {
  state.rules = [{ index: "1" }];
  assert.equal(await loadRulesSnapshot(), false);
  assert.deepEqual(state.rules, []);
  runEngine();
  host.respond("rules_snapshot", { rules: [{ index: 3, type: "DOMAIN", payload: "a.test", proxy: "Proxy", provider: "p", hits: 9, size: 2, extra: { x: 1 } }, {}] });
  assert.equal(await loadRulesSnapshot(), true);
  assert.deepEqual(state.rules, [
    { index: "3", type: "DOMAIN", payload: "a.test", proxy: "Proxy", provider: "p", hits: "9", size: 2, extra: { x: 1 } },
    { index: "unavailable", type: "", payload: "", proxy: "", provider: "", hits: "unavailable", size: "unavailable", extra: {} },
  ]);
  host.respond("rules_snapshot", { rules: "not a list" });
  assert.equal(await loadRulesSnapshot(), true);
  assert.deepEqual(state.rules, []);
  host.respond("rules_snapshot", new Error("no rules endpoint"));
  assert.equal(await loadRulesSnapshot(), false);
  assert.equal(lastLog().message, "no rules endpoint");
  host.respond("rules_snapshot", () => { replaceEngineIdentity(); return { rules: [{}] }; });
  assert.equal(await loadRulesSnapshot(), false);
  const token = captureEngineIdentityToken();
  replaceEngineIdentity();
  state.rules = [{ index: "kept" }];
  assert.equal(await loadRulesSnapshot(token), false);
  assert.deepEqual(state.rules, [{ index: "kept" }], "a stale request while running does not clear the rules");
});

test("connections are closed after a proxy change only for the engine that changed", async () => {
  assert.equal(await closeConnectionsAfterProxyChange("mode"), false);
  runEngine();
  assert.equal(await closeConnectionsAfterProxyChange("mode"), true, "nothing open, nothing to close");
  state.connections = [{ id: "a" }];
  host.respond("close_all_connections", null);
  assert.equal(await closeConnectionsAfterProxyChange("mode"), true);
  assert.deepEqual(state.connections, []);
  assert.equal(lastLog().message, "Closed 1 connection(s) after mode switch");
  state.connections = [{ id: "a" }];
  host.respond("close_all_connections", new Error("busy"));
  assert.equal(await closeConnectionsAfterProxyChange("Proxy"), false);
  assert.equal(state.controllerStatus, "controller offline");
  assert.equal(lastLog().message, "Connection cleanup after Proxy switch failed: busy");
  assert.equal(await closeConnectionsAfterProxyChange("Proxy", captureEngineIdentityToken(), () => false), false);
  host.respond("close_all_connections", () => { replaceEngineIdentity(); return null; });
  assert.equal(await closeConnectionsAfterProxyChange("Proxy"), false);
  runEngine();
  host.respond("close_all_connections", () => { replaceEngineIdentity(); return new Error("late"); });
  state.logs = [];
  assert.equal(await closeConnectionsAfterProxyChange("Proxy"), false);
  assert.equal(state.logs.length, 0);
});

test("a controller snapshot keeps measured delays and in-flight results while a delay test runs", () => {
  applyControllerSnapshot(null);
  state.runtimeSettings = { settings: { allow_lan: true } };
  applyControllerSnapshot({ config: { mode: "GLOBAL", log_level: "debug" }, proxies: { groups: [] } });
  assert.equal(state.mode, "Global");
  assert.equal(state.logLevel, "debug");
  assert.equal(state.toggles.allowLan, true);
  state.runtimeSettings = null;
  applyControllerSnapshot({ config: { mode: "weird" } });
  assert.equal(state.mode, null);
  assert.equal(state.toggles.allowLan, false);
  assert.equal(state.logLevel, null);

  state.proxyDelayResults.set("JP", { delay: null, delayFailure: "timeout" });
  applyControllerSnapshot(snapshot());
  const [group] = state.proxyGroups;
  assert.deepEqual(group.options.map(({ name, delay, dead, kind, udp }) => ({ name, delay, dead, kind, udp })), [
    { name: "HK", delay: 80, dead: false, kind: "Shadowsocks", udp: true },
    { name: "JP", delay: null, dead: true, kind: "Trojan", udp: null },
  ]);
  state.proxyDelayResults.clear();
  state.toggles.testingDelays = true;
  group.options[0].delay = "pending";
  applyControllerSnapshot(snapshot());
  assert.equal(state.proxyGroups[0].options[0].delay, "pending");
});

test("an automatic group with no listed options still shows the node it observed", () => {
  applyControllerSnapshot(snapshot({ kind: "URLTest", options: [], selected: "HK" }));
  assert.equal(state.proxyGroups[0].observedOption.name, "HK");
  applyControllerSnapshot(snapshot({ kind: "Selector", options: [], selected: "HK" }));
  assert.equal(state.proxyGroups[0].observedOption, null, "a manual group never invents an option");
  applyControllerSnapshot(snapshot({ kind: "URLTest", options: [], selected: "Gone" }));
  assert.equal(state.proxyGroups[0].observedOption, null);
  applyControllerSnapshot({ config: {}, proxies: { groups: [{ name: "G" }] } });
  assert.deepEqual(state.proxyGroups[0], { name: "G", type: undefined, now: "DIRECT", options: [], observedOption: null });
});

test("connection snapshots derive rows, per-row speed and traffic from consecutive totals", () => {
  applyConnectionsSnapshot(null);
  const realNow = Date.now;
  try {
    Date.now = () => 10_000;
    applyConnectionsSnapshot({ uploadTotal: 1000, download_total: 2000, connections: [
      { id: "a", upload: 100, download: 200, start: "2026-01-01T10:20:30Z", rulePayload: "example.test", rule: "DOMAIN",
        chains: ["Proxy"], metadata: { host: "example.test" } },
      { id: "b", metadata: { destinationIP: "1.2.3.4" } },
      { id: "c" },
    ] });
    assert.deepEqual(state.connections.map(({ host, rule, age }) => ({ host, rule, age })), [
      { host: "example.test", rule: "DOMAIN,example.test", age: "10:20:30" },
      { host: "1.2.3.4", rule: "MATCH", age: "live" },
      { host: "unknown", rule: "MATCH", age: "live" },
    ]);
    assert.equal(state.controllerStatus, "controller live stream");
    Date.now = () => 12_000;
    applyConnectionsSnapshot({ upload: 1000 + 2 * 1024 * 1024, download: 2000, connections: [
      { id: "a", upload: 2148, download: 200, metadata: { destination_ip: "5.6.7.8" }, rule_payload: "x" },
    ] });
    const [row] = state.connections;
    assert.equal(row.uploadSpeedBytes, 1024);
    assert.equal(row.downloadSpeedBytes, 0);
    assert.equal(state.traffic.upload, 1);
    assert.equal(state.traffic.download, 0);
  } finally {
    Date.now = realNow;
  }
});

test("clearing controller state forgets every controller-backed view", () => {
  state.mode = "Rule";
  state.proxyGroups = [{}];
  state.connections = [{}];
  state.closingConnectionIds.add("a");
  state.connectionDetailId = "a";
  clearControllerBackedState();
  assert.equal(state.mode, null);
  assert.deepEqual(state.proxyGroups, []);
  assert.deepEqual(state.connections, []);
  assert.equal(state.closingConnectionIds.size, 0);
  assert.equal(state.connectionDetailId, null);
});

function mutation(overrides = {}) {
  return {
    lane: "proxy-mode",
    kind: "mode",
    target: "Global",
    source: "mode",
    failureLabel: "Proxy mode Global was not applied",
    successMessage: "Proxy mode switched to Global",
    breakConnectionsReason: "mode",
    invokeMutation: () => Promise.resolve(),
    readObserved: (value) => value.config.mode[0].toUpperCase() + value.config.mode.slice(1),
    publishObserved: (observed) => { state.mode = observed; },
    ...overrides,
  };
}

test("a controller mutation is shown as requested and confirmed by reading the controller back", async () => {
  runEngine();
  const renderPage = spy();
  const { enqueueControllerMutation } = createControllerMutations({ renderPage });
  host.respond("controller_snapshot", snapshot({ mode: "global" }));
  host.respond("refresh_tray_menu", null);
  const done = enqueueControllerMutation(mutation());
  assert.equal(state.mode, "Global", "the requested mode is shown while it is pending");
  assert.equal(await done, true);
  assert.equal(lastLog().message, "Proxy mode switched to Global");
  assert.equal(runtime.controllerMutationPendingByLane.size, 0);
  assert.ok(renderPage.count() >= 2);
});

test("a mutation the controller did not apply, could not confirm or refused is reported with the readback", async () => {
  runEngine();
  const { enqueueControllerMutation } = createControllerMutations({ renderPage: spy() });
  host.respond("refresh_tray_menu", null);
  host.respond("controller_snapshot", snapshot({ mode: "rule" }));
  assert.equal(await enqueueControllerMutation(mutation()), false);
  assert.equal(lastLog().message, "Proxy mode Global was not applied: controller readback reported Rule");
  assert.equal(state.mode, "Rule", "the observed mode is published");

  host.respond("controller_snapshot", null);
  assert.equal(await enqueueControllerMutation(mutation()), false);
  assert.equal(lastLog().message, "Proxy mode Global was not applied: controller readback was unavailable");

  host.respond("controller_snapshot", snapshot({ mode: "rule" }));
  assert.equal(await enqueueControllerMutation(mutation({ invokeMutation: () => Promise.reject(new Error("bad mode")) })), false);
  assert.equal(lastLog().message, "Proxy mode Global was not applied: bad mode; controller readback reports Rule");
  host.respond("controller_snapshot", null);
  assert.equal(await enqueueControllerMutation(mutation({ invokeMutation: () => Promise.reject(new Error("bad mode")) })), false);
  assert.equal(lastLog().message, "Proxy mode Global was not applied: bad mode; controller readback was unavailable");
});

test("a confirmed mutation closes existing connections when that preference is on", async () => {
  runEngine();
  state.toggles.breakOnProxyChange = true;
  state.connections = [{ id: "a" }];
  const { enqueueControllerMutation } = createControllerMutations({ renderPage: spy() });
  host.respond("controller_snapshot", snapshot({ mode: "global" }));
  host.respond("refresh_tray_menu", null);
  host.respond("close_all_connections", null);
  assert.equal(await enqueueControllerMutation(mutation()), true);
  assert.ok(messages().includes("Closed 1 connection(s) after mode switch"));
});

test("a newer mutation of the same lane supersedes a queued one and an engine change cancels both", async () => {
  runEngine();
  const { enqueueControllerMutation } = createControllerMutations({ renderPage: spy() });
  host.respond("refresh_tray_menu", null);
  host.respond("controller_snapshot", snapshot({ mode: "direct" }));
  let release;
  const first = enqueueControllerMutation(mutation({ invokeMutation: () => new Promise((resolve) => { release = resolve; }) }));
  const second = enqueueControllerMutation(mutation({ target: "Rule" }));
  const third = enqueueControllerMutation(mutation({ target: "Direct" }));
  release();
  assert.deepEqual(await Promise.all([first, second, third]), [false, false, true]);

  replaceEngineIdentity();
  assert.equal(await enqueueControllerMutation(mutation()), false, "a stale engine identity admits no mutation");
  stopEngine();
  assert.equal(await enqueueControllerMutation(mutation()), false);
});

test("a mutation overtaken by the engine at any stage resolves without reporting", async () => {
  for (const stage of ["invoke", "read", "break"]) {
    runEngine();
    state.logs = [];
    state.toggles.breakOnProxyChange = stage === "break";
    state.connections = [{ id: "a" }];
    const { enqueueControllerMutation } = createControllerMutations({ renderPage: spy() });
    host.respond("refresh_tray_menu", null);
    host.respond("controller_snapshot", () => {
      if (stage === "read") replaceEngineIdentity();
      return snapshot({ mode: "global" });
    });
    host.respond("close_all_connections", () => { replaceEngineIdentity(); return null; });
    const invokeMutation = async () => { if (stage === "invoke") replaceEngineIdentity(); };
    assert.equal(await enqueueControllerMutation(mutation({ invokeMutation })), false, stage);
    assert.deepEqual(state.logs.filter((entry) => entry.source === "mode"), [], stage);
  }
});

function commands(overrides = {}) {
  return createProxyCommands({
    renderPage: spy(),
    enqueueControllerMutation: spy(async () => true),
    freshProxyControllerSnapshotAvailable: () => true,
    loadProfilesSnapshot: spy(async () => true),
    ...overrides,
  });
}

test("the proxy mode needs a valid mode, a running engine and a fresh snapshot", async () => {
  await assert.rejects(() => commands().applyProxyMode("Sideways"), /Proxy mode is invalid/u);
  assert.equal(await commands().applyProxyMode("Global"), undefined);
  assert.equal(lastLog().message, "Proxy mode Global is unavailable while the engine is Off");
  runEngine();
  assert.equal(await commands({ freshProxyControllerSnapshotAvailable: () => false }).applyProxyMode("Rule"), false);
  assert.equal(lastLog().message, "Proxy mode Rule requires a fresh controller snapshot");
  const enqueue = spy(async () => true);
  host.respond("set_proxy_mode", null);
  assert.equal(await commands({ enqueueControllerMutation: enqueue }).applyProxyMode("Direct"), true);
  const [[spec]] = enqueue.calls;
  assert.equal(spec.lane, "proxy-mode");
  assert.equal(spec.readObserved(snapshot({ mode: "direct" })), "Direct");
  spec.publishObserved("Rule");
  assert.equal(state.mode, "Rule");
  await spec.invokeMutation();
  assert.deepEqual(host.argsOf("set_proxy_mode"), [{ mode: "Direct" }]);
});

test("a live proxy selection is checked against the snapshot before it is queued", async () => {
  runEngine();
  state.proxyGroups = [
    { name: "Proxy", type: "Selector", now: "HK", options: [{ name: "HK" }, { name: "JP" }] },
    { name: "Auto", type: "URLTest", now: "HK", options: [{ name: "HK" }] },
  ];
  assert.equal(await commands().applyProxySelection("Missing", "HK"), false);
  assert.equal(await commands({ freshProxyControllerSnapshotAvailable: () => false }).applyProxySelection("Proxy", "JP"), false);
  assert.equal(lastLog().message, "Proxy selection requires a fresh controller snapshot");
  assert.equal(await commands().applyProxySelection("Auto", "HK"), false);
  assert.equal(lastLog().message, "The current proxy group is selected by the engine and is read-only");
  assert.equal(await commands().applyProxySelection("Proxy", "SG"), false);
  assert.equal(lastLog().message, "Proxy selection is not an option in the current controller snapshot");
  const enqueue = spy(async () => true);
  host.respond("select_proxy", null);
  assert.equal(await commands({ enqueueControllerMutation: enqueue }).applyProxySelection("Proxy", "JP"), true);
  const [[spec]] = enqueue.calls;
  assert.equal(spec.lane, "proxy-selector:Proxy");
  assert.equal(spec.readObserved(snapshot({ selected: "JP" })), "JP");
  assert.equal(spec.readObserved({ proxies: { groups: [{ name: "Proxy", options: ["SG"] }] } }), "SG");
  assert.equal(spec.readObserved({ proxies: { groups: [{ name: "Proxy" }] } }), "DIRECT");
  assert.equal(spec.readObserved({}), null);
  spec.publishObserved("JP");
  assert.equal(state.proxyGroups[0].now, "JP");
  spec.publishObserved(null);
  assert.equal(state.proxyGroups[0].now, "JP", "an unknown observation changes nothing");
  await spec.invokeMutation();
  assert.deepEqual(host.argsOf("select_proxy"), [{ group: "Proxy", proxy: "JP" }]);
  stopEngine();
  assert.equal(await commands({ freshProxyControllerSnapshotAvailable: () => false }).applyProxySelection("Proxy", "JP"), false);
  assert.equal(lastLog().message, "Selecting proxy in Proxy is unavailable while the engine is Off");
});

test("while Off a selection is saved to the profile and confirmed by reading it back", async () => {
  const policy = (now) => ({ profileId: "work", groups: [
    { name: "Proxy", type: "Selector", now, options: [{ name: "HK" }, { name: "JP" }] },
    { name: "Auto", type: "URLTest", now: "HK", options: [{ name: "HK" }] },
  ] });
  state.savedProfilePolicy = policy("HK");
  const renderPage = spy();
  const loadProfilesSnapshot = spy(async () => { state.savedProfilePolicy = policy("JP"); return true; });
  host.respond("select_proxy", null);
  assert.equal(await commands({ renderPage, loadProfilesSnapshot }).applyProxySelection("Proxy", "JP"), true);
  assert.deepEqual(host.argsOf("select_proxy"), [{ profileId: "work", group: "Proxy", proxy: "JP" }]);
  assert.equal(lastLog().message, "Saved JP for Proxy; it will apply on the next start");
  assert.equal(state.savedProxySelectionBusy, false);
  assert.equal(renderPage.count(), 1);

  for (const [group, proxy] of [["Auto", "HK"], ["Proxy", "SG"], ["Missing", "HK"]]) {
    assert.equal(await commands().applyProxySelection(group, proxy), false, `${group}/${proxy}`);
  }
  state.savedProxySelectionBusy = true;
  assert.equal(await commands().applyProxySelection("Proxy", "JP"), false, "one saved selection at a time");
  state.savedProxySelectionBusy = false;

  state.savedProfilePolicy = policy("HK");
  assert.equal(await commands({ loadProfilesSnapshot: spy(async () => true) }).applyProxySelection("Proxy", "JP"), false);
  assert.equal(lastLog().message, "Saved proxy selection could not be confirmed");
  host.respond("select_proxy", new Error("profile locked"));
  assert.equal(await commands().applyProxySelection("Proxy", "JP"), false);
  assert.equal(lastLog().message, "profile locked");
  assert.equal(state.savedProxySelectionBusy, false);
});

test("live streams start for a running engine and stop when it stops, reporting each failure", async () => {
  runEngine();
  host.respond("start_connections_stream", streamBinding("connections"));
  host.respond("start_log_stream", new Error("log stream refused"));
  await startLiveStreams();
  assert.deepEqual(host.commands(), ["start_connections_stream", "start_log_stream"]);
  assert.equal(lastLog().message, "Live stream unavailable: log stream refused");
  assert.equal(runtime.connectionsLiveStream.binding.stream_id, 1);

  host.respond("start_connections_stream", () => { replaceEngineIdentity(); return streamBinding("connections", 2); });
  host.respond("stop_connections_stream", null);
  state.logs = [];
  runEngine();
  await startLiveStreams();
  assert.equal(host.commands().filter((command) => command === "start_log_stream").length, 1, "an engine change ends the pass");
  host.respond("start_connections_stream", () => { replaceEngineIdentity(); return new Error("late"); });
  await startLiveStreams();
  assert.equal(state.logs.length, 0, "a stale failure is not reported");
});

test("pending intents show the requested mode and node of the current engine only", async () => {
  const { applyPendingControllerIntents, invalidateControllerMutationIntents } = await import("../src/controller-intents.js");
  runEngine();
  state.mode = "Rule";
  state.proxyGroups = [{ name: "Proxy", now: "HK", options: [] }];
  const token = captureEngineIdentityToken();
  runtime.controllerMutationPendingByLane.set("proxy-mode", { epoch: 1, token, kind: "mode", target: "Global" });
  runtime.controllerMutationPendingByLane.set("proxy-selector:Proxy", { epoch: 2, token, kind: "selector", groupName: "Proxy", target: "JP" });
  runtime.controllerMutationPendingByLane.set("proxy-selector:Gone", { epoch: 3, token, kind: "selector", groupName: "Gone", target: "JP" });
  applyPendingControllerIntents();
  assert.equal(state.mode, "Global");
  assert.equal(state.proxyGroups[0].now, "JP");
  replaceEngineIdentity();
  state.mode = "Rule";
  applyPendingControllerIntents();
  assert.equal(state.mode, "Rule", "an intent of an earlier engine is not shown");

  const resolved = [];
  runtime.controllerMutationLatestByLane.set("proxy-mode", 1);
  runtime.controllerMutationQueue.push({ resolve: (value) => resolved.push(value) }, { resolve: (value) => resolved.push(value) });
  invalidateControllerMutationIntents();
  assert.deepEqual(resolved, [false, false]);
  assert.equal(runtime.controllerMutationLatestByLane.size, 0);
  assert.equal(runtime.controllerMutationPendingByLane.size, 0);
  assert.equal(runtime.controllerMutationQueue.length, 0);
});

test("a queued stream change that a newer one replaced before it ran does nothing", async () => {
  runEngine();
  host.respond("start_connections_stream", streamBinding("connections"));
  const first = setConnectionsStreamRunning(true);
  const second = setConnectionsStreamRunning(true);
  assert.equal(await first, false, "the replaced request is skipped");
  assert.equal(await second, true);
  assert.equal(host.argsOf("start_connections_stream").length, 1, "only the newest request reaches the host");
});
