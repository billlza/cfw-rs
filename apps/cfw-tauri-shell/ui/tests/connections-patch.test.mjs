import { dom, element, host, settle, spy } from "./support/fake-host.mjs";
import { replaceEngineIdentity, runEngine, stopEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state, runtime, MAX_CONNECTION_ROWS } from "../src/state.js";
import { createConnectionsView } from "../src/connections.js";
import { errorText, escapeHtml, formatBytes, safeRegex } from "../src/text-format.js";
import { invoke } from "../src/ipc.js";
import { appendLog } from "../src/app-log.js";
import { captureEngineIdentityToken, controllerActionAllowed, engineIdentityTokenIsCurrent } from "../src/engine-identity.js";
import { loadControllerSnapshot } from "../src/controller-reads.js";

const lastLog = () => state.logs[0];

function view(overrides = {}) {
  const d = {
    state, runtime, MAX_CONNECTION_ROWS, safeRegex, escapeHtml, formatBytes, renderPage: spy(), bindPageEvents: spy(),
    controllerActionAllowed, captureEngineIdentityToken, engineIdentityTokenIsCurrent, invoke, loadControllerSnapshot,
    appendLog, errorText, ...overrides,
  };
  return { d, connections: createConnectionsView(d) };
}

/// A row element as the page parses it from `connectionRowHtml`.
function rowElement(id) {
  const parts = Object.fromEntries(["[data-conn-up]", "[data-conn-down]", "[data-conn-speed]", "[data-close-connection]"]
    .map((selector) => [selector, element("span", { dataset: { closeConnection: id } })]));
  const row = element("article", { querySelector: (selector) => parts[selector] ?? null, querySelectorAll: () => [] });
  row.setAttribute("data-connection-id", id);
  row.parts = parts;
  row.removed = false;
  row.remove = () => {
    row.removed = true;
    if (row.parent) row.parent.children = row.parent.children.filter((child) => child !== row);
  };
  return row;
}

/// The scroll container keeps its children in order, as the DOM does.
function scrollElement(rows) {
  const scroll = element("div", { children: [...rows] });
  for (const row of rows) row.parent = scroll;
  scroll.querySelectorAll = (selector) => (selector === "[data-connection-id]" ? [...scroll.children] : []);
  scroll.insertBefore = (node, reference) => {
    node.parent = scroll;
    scroll.children = scroll.children.filter((child) => child !== node);
    const index = reference ? scroll.children.indexOf(reference) : scroll.children.length;
    scroll.children.splice(index < 0 ? scroll.children.length : index, 0, node);
  };
  return scroll;
}

function connection(id, overrides = {}) {
  return { id, host: `${id}.test`, rule: "MATCH", chains: ["Proxy"], upload: "1 B", download: "2 B", speed: "1 B/s up · 0 B/s down",
    uploadBytes: 1, downloadBytes: 2, uploadSpeedBytes: 1, downloadSpeedBytes: 0, start: "2026-01-01T00:00:00Z", metadata: {}, ...overrides };
}

beforeEach(() => {
  host.reset();
  dom.reset();
  state.logs = [];
  state.activePage = "connections";
  state.connections = [];
  state.connectionSearch = "";
  state.connectionSort = "age";
  state.connectionSortDesc = false;
  state.connectionDetailId = null;
  state.closingAllConnections = false;
  state.closingConnectionIds.clear();
  state.connectionStream = { at: 0, uploadTotal: 2048, downloadTotal: 4096, rows: new Map() };
  runtime.connectionRowEls = null;
  runtime.connectionsPatchFrame = null;
  stopEngine();
});

test("a patch without its page renders the page instead", async () => {
  const { d, connections } = view();
  connections.scheduleConnectionsPatch();
  connections.scheduleConnectionsPatch();
  await settle();
  assert.equal(d.renderPage.count(), 1, "one frame for a burst, and no page to patch means a render");
  dom.set("[data-connections-root]", element("section"));
  dom.set("[data-conn-scroll]", scrollElement([]));
  state.activePage = "logs";
  connections.scheduleConnectionsPatch();
  await settle();
  assert.equal(d.renderPage.count(), 2);
});

test("a patch updates totals and rows in place, adds new rows, drops gone ones and keeps their order", async () => {
  const { d, connections } = view();
  const totals = element("span");
  const closeAll = element("button");
  const root = element("section", { querySelector: (selector) => ({ "[data-conn-totals]": totals, "[data-conn-close-all]": closeAll })[selector] ?? null });
  dom.set("[data-connections-root]", root);
  const kept = rowElement("b");
  const gone = rowElement("z");
  const scroll = dom.set("[data-conn-scroll]", scrollElement([gone, kept]));
  const created = [];
  document.createElement = () => {
    const wrap = element("div");
    Object.defineProperty(wrap, "innerHTML", { set(html) {
      const id = /data-connection-id="([^"]+)"/u.exec(html)[1];
      wrap.firstElementChild = rowElement(id);
      created.push(wrap.firstElementChild);
    } });
    return wrap;
  };
  state.connections = [connection("a", { start: "2026-01-01T00:00:00Z" }), connection("b", { start: "2026-01-02T00:00:00Z", speed: undefined })];
  state.closingConnectionIds.add("b");
  connections.scheduleConnectionsPatch();
  await settle();
  assert.equal(totals.textContent, "Total: ↑ 2.0 KB ↓ 4.0 KB");
  assert.equal(closeAll.textContent, "Close All (2)");
  assert.equal(gone.removed, true);
  assert.deepEqual(created.map((row) => row.getAttribute("data-connection-id")), ["a"]);
  assert.deepEqual(scroll.children.map((row) => row.getAttribute("data-connection-id")), ["a", "b"]);
  assert.equal(kept.parts["[data-conn-speed]"].textContent, "0 B/s");
  assert.equal(kept.parts["[data-close-connection]"].textContent, "Closing");
  assert.equal(kept.parts["[data-close-connection]"].disabled, true);
  assert.equal(created[0].parts["[data-close-connection]"].textContent, "Close");
  assert.equal(d.renderPage.count(), 0);

  state.closingAllConnections = true;
  state.connectionDetailId = "a";
  root.insertAdjacentHTML = spy();
  connections.scheduleConnectionsPatch();
  await settle();
  assert.equal(closeAll.textContent, "Closing...");
  assert.equal(closeAll.disabled, true);
  assert.match(root.insertAdjacentHTML.calls[0][1], /Connection Info/u);
  assert.equal(d.bindPageEvents.count(), 1);

  const modal = element("div");
  modal.remove = spy();
  root.querySelector = (selector) => (selector === ".modal-backdrop" ? modal : null);
  state.connectionDetailId = null;
  connections.scheduleConnectionsPatch();
  await settle();
  assert.equal(modal.remove.count(), 1, "a closed detail is removed");
  root.querySelector = () => null;
  connections.scheduleConnectionsPatch();
  await settle();
});

test("facets count the busiest rules and chains", () => {
  const { connections } = view();
  const facets = connections.connectionFacets([
    connection("a", { rule: "DOMAIN", chains: ["HK", "Proxy"] }),
    connection("b", { rule: "DOMAIN", chains: ["HK"] }),
    connection("c", { rule: "", chains: undefined }),
  ]);
  assert.deepEqual(facets.rules, [["DOMAIN", 2]]);
  assert.deepEqual(facets.chains, [["HK", 2], ["Proxy", 1]]);
});

test("the connection detail lists its fields with copy buttons", () => {
  const { connections } = view();
  state.connections = [connection("a", { metadata: { network: "tcp", empty: "", missing: null } })];
  state.connectionDetailId = "a";
  const html = connections.renderConnections();
  assert.match(html, /<dt>Host<\/dt>\s*<dd>a\.test<\/dd>/u);
  assert.match(html, /<dt>network<\/dt>\s*<dd>tcp<\/dd>/u);
  assert.doesNotMatch(html, /<dt>empty<\/dt>/u);
  assert.match(html, /data-copy-text="Proxy"/u);
});

test("a row opens its detail and closes its connection on the running engine", async () => {
  const { d, connections } = view();
  const detail = element("button", { dataset: { connectionDetail: "a" } });
  const close = element("button", { dataset: { closeConnection: "a" } });
  const scope = { querySelectorAll: (selector) => ({ "[data-connection-detail]": [detail], "[data-close-connection]": [close] })[selector] ?? [] };
  connections.bindConnectionRowEvents(scope);
  await detail.fire("click");
  assert.equal(state.connectionDetailId, "a");
  await close.fire("click");
  assert.equal(lastLog().message, "Closing connection a is unavailable while the engine is Off");

  runEngine();
  host.respond("close_connection", null);
  host.respond("controller_snapshot", null);
  await close.fire("click");
  assert.deepEqual(host.argsOf("close_connection"), [{ id: "a" }]);
  assert.equal(lastLog().message, "Connection a closed");
  assert.equal(state.closingConnectionIds.has("a"), false);

  host.respond("close_connection", new Error("unknown id"));
  await close.fire("click");
  assert.equal(state.controllerStatus, "controller offline");
  assert.equal(lastLog().message, "Controller close failed for a: unknown id");

  const renders = d.renderPage.count();
  host.respond("close_connection", () => { replaceEngineIdentity(); return null; });
  await close.fire("click");
  assert.equal(state.closingConnectionIds.has("a"), true, "a stale request leaves the new engine's state alone");
  state.closingConnectionIds.clear();
  runEngine();
  host.respond("close_connection", () => { replaceEngineIdentity(); return new Error("late"); });
  await close.fire("click");
  runEngine();
  host.respond("close_connection", null);
  host.respond("controller_snapshot", () => { replaceEngineIdentity(); return null; });
  await close.fire("click");
  assert.equal(d.renderPage.count(), renders + 3, "each stale close renders only its busy state");
});

test("connections are searched across their metadata and sorted by any column", () => {
  const { connections } = view();
  state.connections = [
    connection("a", { host: "b.test", uploadBytes: 5, downloadBytes: 1, uploadSpeedBytes: 1, downloadSpeedBytes: 1, metadata: { network: "udp" } }),
    connection("b", { host: "a.test", uploadBytes: 1, downloadBytes: 9, uploadSpeedBytes: 5, downloadSpeedBytes: 5, start: "" }),
  ];
  const order = () => [...connections.renderConnections().matchAll(/data-connection-id="([^"]+)"/gu)].map((match) => match[1]);
  for (const [sort, expected] of [["host", ["b", "a"]], ["speed", ["a", "b"]], ["upload", ["b", "a"]], ["download", ["a", "b"]], ["age", ["b", "a"]]]) {
    state.connectionSort = sort;
    assert.deepEqual(order(), expected, sort);
  }
  state.connectionSortDesc = true;
  state.connectionSort = "host";
  assert.deepEqual(order(), ["a", "b"]);
  state.connectionSearch = "udp";
  assert.deepEqual(order(), ["a"]);
  state.connectionSearch = "^a\\.";
  assert.deepEqual(order(), ["b"], "a search is a regular expression when it parses as one");
});
