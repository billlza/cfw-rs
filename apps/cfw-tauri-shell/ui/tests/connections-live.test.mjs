import assert from "node:assert/strict";
import test from "node:test";
import { createConnectionsView } from "../src/connections.js";
import { safeRegex } from "../src/format.js";

test("connection ordering remains stable, bounded and responsive to changed snapshots", () => {
  const connections = [
    { id: "new", host: "c.example", start: "2026-09-25T02:00:00Z" },
    { id: "invalid", host: "a[example", start: "not-a-date" },
    { id: "tie-a", host: "b.example", start: "2026-09-25T01:00:00Z", metadata: { process_path: "/Applications/Test.app" } },
    { id: "tie-b", host: "b.example", start: "2026-09-25T01:00:00Z" },
  ];
  const state = {
    connections, connectionSearch: "", connectionSort: "age", connectionSortDesc: false,
    connectionStream: {}, toggles: {}, closingConnectionIds: new Set(),
  };
  const view = createConnectionsView({
    state, runtime: {}, MAX_CONNECTION_ROWS: 3, safeRegex,
    escapeHtml: (value) => String(value ?? ""), formatBytes: String,
  });
  const visibleIds = () => [...view.renderConnections().matchAll(/data-connection-id="([^"]+)"/gu)].map((match) => match[1]);
  assert.deepEqual(visibleIds(), ["invalid", "tie-a", "tie-b"]);
  state.connectionSortDesc = true;
  assert.deepEqual(visibleIds(), ["new", "tie-a", "tie-b"]);
  assert.deepEqual(connections.map(({ id }) => id), ["new", "invalid", "tie-a", "tie-b"]);
  connections[3] = { ...connections[3], start: "2026-09-25T03:00:00Z" };
  assert.deepEqual(visibleIds(), ["tie-b", "new", "tie-a"]);
  state.connectionSearch = "[";
  assert.deepEqual(visibleIds(), ["invalid"]);
  state.connectionSearch = "test\\.app|c\\.example";
  assert.deepEqual(visibleIds(), ["new", "tie-a"]);
  state.connectionSearch = "";
  state.connectionSort = "host";
  state.connectionSortDesc = false;
  assert.deepEqual(visibleIds(), ["invalid", "tie-a", "tie-b"]);
});

test("streamed rows keep their sort position and receive working actions once", () => {
  const row = (id) => {
    const buttons = Object.fromEntries(["detail", "close"].map((kind) => [kind, {
      dataset: kind === "detail" ? { connectionDetail: id } : { closeConnection: id },
      listeners: [],
      addEventListener(_event, listener) { this.listeners.push(listener); },
    }]));
    return {
      id, buttons,
      getAttribute: () => id,
      querySelector: (selector) => selector === "[data-close-connection]" ? buttons.close : null,
      querySelectorAll: (selector) => selector === "[data-close-connection]" ? [buttons.close]
        : selector === "[data-connection-detail]" ? [buttons.detail] : [],
      remove() { scroll.children.splice(scroll.children.indexOf(this), 1); },
    };
  };
  const scroll = {
    children: [row("a"), row("c")],
    querySelectorAll() { return this.children; },
    insertBefore(element, before) {
      const old = this.children.indexOf(element);
      if (old !== -1) this.children.splice(old, 1);
      this.children.splice(before ? this.children.indexOf(before) : this.children.length, 0, element);
    },
  };
  const root = { querySelector: () => null };
  const previousDocument = globalThis.document;
  const previousWindow = globalThis.window;
  let scheduled;
  globalThis.document = {
    querySelector: (selector) => selector === "[data-connections-root]" ? root : scroll,
    createElement: () => ({
      set innerHTML(html) { this.firstElementChild = row(html.match(/data-connection-id="([^"]+)"/u)[1]); },
    }),
  };
  globalThis.window = { requestAnimationFrame: (callback) => { scheduled = callback; return 1; } };
  try {
    const state = {
      activePage: "connections", connectionSearch: "", connectionSort: "host", connectionSortDesc: false,
      connectionStream: {}, toggles: {}, closingConnectionIds: new Set(),
      connections: [
        { id: "new", host: "1-new" }, { id: "c", host: "2-c" }, { id: "a", host: "3-a" },
      ],
    };
    const runtime = { connectionsPatchFrame: null };
    const attempts = [];
    let renders = 0;
    const view = createConnectionsView({
      state, runtime, MAX_CONNECTION_ROWS: 512, safeRegex: () => null,
      escapeHtml: (value) => String(value ?? ""), formatBytes: String,
      renderPage: () => { renders += 1; }, bindPageEvents: () => {},
      controllerActionAllowed: (action) => { attempts.push(action); return false; },
    });
    for (const existing of scroll.children) view.bindConnectionRowEvents(existing);
    view.scheduleConnectionsPatch(); scheduled();
    assert.deepEqual(scroll.children.map(({ id }) => id), ["new", "c", "a"]);
    view.scheduleConnectionsPatch(); scheduled();
    for (const current of scroll.children) {
      assert.equal(current.buttons.detail.listeners.length, 1);
      assert.equal(current.buttons.close.listeners.length, 1);
    }
    const added = scroll.children[0];
    added.buttons.detail.listeners[0]({ currentTarget: added.buttons.detail });
    assert.equal(state.connectionDetailId, "new");
    assert.equal(renders, 1);
    added.buttons.close.listeners[0]({ currentTarget: added.buttons.close });
    assert.deepEqual(attempts, ["Closing connection new"]);
  } finally {
    globalThis.document = previousDocument;
    globalThis.window = previousWindow;
  }
});
