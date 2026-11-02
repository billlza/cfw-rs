import { clipboard, dom, element, host, settle, spy } from "./support/fake-host.mjs";
import { replaceEngineIdentity, runEngine, stopEngine, streamBinding } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state, runtime } from "../src/state.js";
import { createConnectionActions } from "../src/connection-actions.js";
import { createLogActions } from "../src/log-actions.js";
import { createRuleActions } from "../src/rule-actions.js";

const lastLog = () => state.logs[0];

beforeEach(() => {
  host.reset();
  dom.reset();
  clipboard.written.length = 0;
  clipboard.writeError = null;
  state.payload = { product: { operating_system: "macos" }, native_ui: {} };
  state.logs = [];
  state.connections = [{ id: "a" }, { id: "b" }];
  state.closingAllConnections = false;
  state.connectionPaused = false;
  state.logsPaused = false;
  state.rules = [];
  state.activePage = "general";
  for (const lane of [runtime.connectionsLiveStream, runtime.logLiveStream]) {
    lane.binding = null;
    lane.desiredRunning = false;
    lane.operation = Promise.resolve();
  }
  stopEngine();
});

const connectionActions = (overrides = {}) => createConnectionActions({ renderPage: spy(), bindConnectionRowEvents: spy(), ...overrides });

test("closing every connection needs a running engine", async () => {
  const renderPage = spy();
  await connectionActions({ renderPage }).actions["close-all"]();
  assert.equal(lastLog().message, "Closing all connections is unavailable while the engine is Off");
  assert.equal(state.controllerStatus, "engine off");
  assert.deepEqual(host.commands(), []);
  assert.equal(renderPage.count(), 0);
});

test("closing every connection reports the count and re-reads the controller", async () => {
  runEngine();
  host.respond("close_all_connections", null);
  host.respond("controller_snapshot", null);
  const renderPage = spy();
  await connectionActions({ renderPage }).actions["close-all"]();
  assert.deepEqual(host.commands().slice(0, 2), ["close_all_connections", "controller_snapshot"]);
  assert.ok(state.logs.some((entry) => entry.level === "warning" && entry.message === "Closed 2 active connections"));
  assert.equal(state.closingAllConnections, false);
  assert.equal(renderPage.count(), 2, "busy, then the result");
});

test("a refused close-all keeps the rows and says the controller is offline", async () => {
  runEngine();
  host.respond("close_all_connections", new Error("controller down"));
  await connectionActions().actions["close-all"]();
  assert.equal(state.controllerStatus, "controller offline");
  assert.equal(lastLog().message, "Controller close-all failed; keeping local rows: controller down");
  assert.equal(state.closingAllConnections, false);
});

test("a close-all answered after the engine changed reports nothing and leaves the new engine's flag", async () => {
  runEngine();
  host.respond("close_all_connections", () => { replaceEngineIdentity(); return null; });
  const renderPage = spy();
  await connectionActions({ renderPage }).actions["close-all"]();
  assert.equal(state.logs.length, 0);
  assert.equal(state.closingAllConnections, true, "the next engine's busy flag is not cleared by a stale request");
  assert.equal(renderPage.count(), 1);
  runEngine();
  host.respond("close_all_connections", () => { replaceEngineIdentity(); return new Error("late"); });
  await connectionActions().actions["close-all"]();
  assert.equal(state.logs.length, 0, "a stale refusal is not reported either");
});

test("the connection stream pauses, resumes on a running engine and restores the flag after a refusal", async () => {
  const { actions } = connectionActions();
  await actions["toggle-connection-stream"]();
  assert.equal(state.connectionPaused, true, "pausing needs no engine");
  await actions["toggle-connection-stream"]();
  assert.equal(lastLog().message, "Starting connection stream is unavailable while the engine is Off");
  assert.equal(state.connectionPaused, true);

  runEngine();
  host.respond("start_connections_stream", streamBinding("connections"));
  await actions["toggle-connection-stream"]();
  assert.equal(state.connectionPaused, false);
  assert.equal(lastLog().message, "Connection stream started");
  host.respond("stop_connections_stream", null);
  await actions["toggle-connection-stream"]();
  assert.equal(lastLog().message, "Connection stream stopped");

  host.respond("start_connections_stream", new Error("stream refused"));
  await actions["toggle-connection-stream"]();
  assert.equal(state.connectionPaused, true, "a refused start stays paused");
  assert.equal(lastLog().message, "Connection stream change failed: stream refused");
});

test("a stream change overtaken by the engine is not reported", async () => {
  runEngine();
  state.connectionPaused = true;
  host.respond("start_connections_stream", () => { replaceEngineIdentity(); return streamBinding("connections"); });
  host.respond("stop_connections_stream", null);
  const renderPage = spy();
  await connectionActions({ renderPage }).actions["toggle-connection-stream"]();
  assert.equal(state.logs.length, 0);
  assert.equal(renderPage.count(), 0);
});

test("connection detail and search are cleared", async () => {
  const renderPage = spy();
  const { actions } = connectionActions({ renderPage });
  state.connectionDetailId = "a";
  state.connectionSearch = "example";
  await actions["close-connection-detail"]();
  await actions["clear-connection-search"]();
  assert.equal(state.connectionDetailId, null);
  assert.equal(state.connectionSearch, "");
  assert.equal(renderPage.count(), 2);
});

test("the Connections page binds rows, search, sorting, copying and facets", async () => {
  const renderPage = spy();
  const bindConnectionRowEvents = spy();
  const search = dom.set("[data-connection-search]", element("input"));
  const byHost = element("button", { dataset: { connectionSort: "host" } });
  const bySpeed = element("button", { dataset: { connectionSort: "speed" } });
  dom.setAll("[data-connection-sort]", [byHost, bySpeed]);
  const copy = element("button", { dataset: { copyText: "example.test" } });
  const empty = element("button", { dataset: {} });
  dom.setAll("[data-copy-text]", [copy, empty]);
  const facet = element("button", { dataset: { connectionFacet: "rule:MATCH" } });
  dom.setAll("[data-connection-facet]", [facet]);
  connectionActions({ renderPage, bindConnectionRowEvents }).bindPage();
  assert.deepEqual(bindConnectionRowEvents.calls, [[document]]);

  await search.fire("input", { currentTarget: { value: "abc" } });
  assert.equal(state.connectionSearch, "abc");
  state.connectionSort = "host";
  state.connectionSortDesc = false;
  await byHost.fire("click");
  assert.equal(state.connectionSortDesc, true, "the same column reverses");
  await bySpeed.fire("click");
  assert.equal(state.connectionSort, "speed");
  assert.equal(state.connectionSortDesc, false, "a new column starts ascending");

  await copy.fire("click");
  await empty.fire("click");
  assert.deepEqual(clipboard.written, ["example.test", ""]);
  assert.equal(lastLog().message, "Connection field copied");
  clipboard.writeError = new Error("denied");
  await copy.fire("click");
  assert.equal(lastLog().level, "warning");
  assert.equal(lastLog().message, "Clipboard API refused copy");

  await facet.fire("click");
  assert.equal(state.connectionSearch, "rule:MATCH");
  assert.equal(renderPage.count(), 7);
});

test("the request log stream follows the same engine and refusal rules", async () => {
  const patchLogStream = spy();
  const renderPage = spy();
  const { actions } = createLogActions({ renderPage, patchLogStream });
  await actions["toggle-log-stream"]();
  assert.equal(state.logsPaused, true);
  await actions["toggle-log-stream"]();
  assert.match(lastLog().message, /Starting request logs is unavailable/u);
  runEngine();
  host.respond("start_log_stream", streamBinding("request-logs"));
  await actions["toggle-log-stream"]();
  assert.equal(lastLog().message, "Request logs started");
  host.respond("stop_log_stream", null);
  await actions["toggle-log-stream"]();
  assert.equal(lastLog().message, "Request logs stopped");
  host.respond("start_log_stream", new Error("busy"));
  await actions["toggle-log-stream"]();
  assert.equal(state.logsPaused, true);
  assert.equal(lastLog().message, "Log stream change failed: busy");
  host.respond("start_log_stream", () => { replaceEngineIdentity(); return streamBinding("request-logs"); });
  const before = renderPage.count();
  await actions["toggle-log-stream"]();
  assert.equal(renderPage.count(), before, "a start overtaken by the engine renders nothing");
});

test("logs are cleared, copied in order and their folder opened per platform", async () => {
  const renderPage = spy();
  const { actions } = createLogActions({ renderPage, patchLogStream: spy() });
  await actions["copy-logs"]();
  assert.deepEqual(clipboard.written, ["(no logs)"]);
  state.logs = [
    { time: "10:00:01", level: "error", message: "second" },
    { at: "10:00:00", message: "first" },
    { payload: "raw" },
  ];
  await actions["copy-logs"]();
  assert.equal(clipboard.written[1], "[10:00:01] error second\n[10:00:00] info first\n[] info raw");
  assert.equal(lastLog().message, "Copied 3 log line(s) to clipboard");
  clipboard.writeError = new Error("denied");
  await actions["copy-logs"]();
  assert.equal(lastLog().message, "Copy logs refused: denied");

  host.respond("reveal_logs_directory", null);
  await actions["reveal-logs"]();
  assert.equal(lastLog().message, "Logs folder opened in Finder");
  state.payload.product.operating_system = "windows";
  await actions["reveal-logs"]();
  assert.equal(lastLog().message, "Logs folder opened in File Explorer");
  host.respond("reveal_logs_directory", new Error("missing"));
  await actions["reveal-logs"]();
  assert.equal(lastLog().message, "Open Folder failed: missing");

  await actions["clear-logs"]();
  assert.deepEqual(state.logs, []);
  assert.equal(renderPage.count(), 7);
});

test("log search patches the stream without a full render", async () => {
  const patchLogStream = spy();
  const search = dom.set("[data-log-search]", element("input"));
  createLogActions({ renderPage: spy(), patchLogStream }).bindPage();
  await search.fire("input", { currentTarget: { value: "timeout" } });
  assert.equal(state.logSearch, "timeout");
  assert.equal(patchLogStream.count(), 1);
  dom.reset();
  createLogActions({ renderPage: spy(), patchLogStream }).bindPage();
});

test("rules open their page, reload from a running engine and page through results", async () => {
  const renderPage = spy();
  const changeRulePage = spy();
  const { actions, bindPage } = createRuleActions({ renderPage, changeRulePage });
  await actions["open-rules"]();
  assert.equal(state.activePage, "rules");
  await actions["reload-rules"]();
  assert.equal(lastLog().message, "Rules reload is unavailable while the engine is Off");
  runEngine();
  host.respond("rules_snapshot", { rules: [{ index: 0, kind: "DOMAIN", payload: "example.test", proxy: "Proxy" }] });
  await actions["reload-rules"]();
  assert.equal(lastLog().message, "Loaded 1 controller rules");
  host.respond("rules_snapshot", new Error("endpoint missing"));
  await actions["reload-rules"]();
  assert.equal(lastLog().message, "Rules controller endpoint unavailable");

  const next = element("button", { dataset: { rulePage: "2" } });
  dom.setAll("[data-rule-page]", [next]);
  const search = dom.set("[data-rule-search]", element("input"));
  bindPage();
  await next.fire("click");
  assert.deepEqual(changeRulePage.calls, [[2]]);
  await search.fire("input", { currentTarget: { value: "DOMAIN" } });
  assert.equal(state.ruleSearch, "DOMAIN");
  assert.equal(renderPage.count(), 5);
  await settle();
});
