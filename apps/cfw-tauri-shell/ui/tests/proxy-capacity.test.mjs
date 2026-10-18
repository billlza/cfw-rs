import assert from "node:assert/strict";
import test from "node:test";
import { createProxyView, indexProxyNodes, PROXY_PAGE_SIZE } from "../src/proxies.js";
import { escapeHtml } from "../src/format.js";
import { createProxyDelayTest, MAX_DELAY_TEST_MILLISECONDS } from "../src/proxy-delay-test.js";

function fixture() {
  const nodes = Array.from({ length: 1024 }, (_, i) => ({ name: `Node-${i}`, kind: "Socks5", delay: null }));
  const groups = Array.from({ length: 32 }, (_, i) => ({ name: `Group-${i}`, type: "Selector", now: "Node-900", options: nodes }));
  const state = { engine: { active: false }, toggles: {}, proxyFilter: "", savedProfilePolicy: { profileId: "capacity", name: "Capacity", groups }, proxyGroupHideTimeouts: new Map(), proxyDelayResults: new Map() };
  const view = createProxyView({ state, runtime: {}, escapeHtml, delayFailureLabel: (x) => x, engineStateLabel: () => "Off", engineIsOff: () => true });
  return { nodes, groups, state, view };
}

test("large subscription pagination reaches every node and selected/filter results", () => {
  const { state, view } = fixture();
  const started = performance.now();
  const seen = new Set();
  for (let page = 0; page < Math.ceil(1024 / PROXY_PAGE_SIZE); page++) {
    const html = view.renderProxies();
    const names = [...html.matchAll(/data-proxy-node="([^"]+)"/gu)].map((match) => match[1]);
    assert.ok(names.length <= PROXY_PAGE_SIZE);
    names.forEach((name) => seen.add(name));
    view.changePage(1);
  }
  assert.equal(seen.size, 1024);
  view.revealSelected("Node-900");
  assert.match(view.renderProxies(), /data-proxy-node="Node-900"/u);
  state.proxyFilter = "Node-1023";
  assert.equal([...view.renderProxies().matchAll(/data-proxy-node=/gu)].length, 1);
  console.log(`capacity UI: 1024 nodes / 32 groups, all pages and selection in ${(performance.now()-started).toFixed(2)} ms`);
});

test("latency updates share an index and invalidate it when the profile is replaced", () => {
  const { nodes, groups, state, view } = fixture();
  const index = indexProxyNodes(groups);
  assert.equal(index.size, 1024);
  assert.equal(index.get("Node-0").size, 1);
  const started = performance.now();
  for (const node of nodes) view.applyDelayToProxyNodes(node.name, 53);
  assert.ok(nodes.every((node) => node.delay === 53));
  const next = { name: "Node-0", delay: null };
  state.savedProfilePolicy.groups = [{ name: "replacement", options: [next] }];
  view.applyDelayToProxyNodes("Node-0", 91);
  assert.equal(next.delay, 91);
  assert.equal(nodes[0].delay, 53);
  console.log(`capacity UI: 1024 latency updates in ${(performance.now()-started).toFixed(2)} ms`);
});

test("latency run stops at its aggregate budget and preserves untested nodes", async () => {
  const { state, nodes } = fixture();
  const runtime = { savedProfilePolicyEpoch: 1 };
  const view = createProxyView({ state, runtime, escapeHtml, delayFailureLabel: (x) => x, engineStateLabel: () => "Off", engineIsOff: () => true });
  const priorDocument = globalThis.document;
  globalThis.document = { hidden: false, querySelector: () => null, querySelectorAll: () => [] };
  let clock = 0;
  let requests = 0;
  try {
    const run = createProxyDelayTest({ state, runtime, view, now: () => clock,
      invoke: async (_command, { proxies }) => { requests++; clock = MAX_DELAY_TEST_MILLISECONDS; return proxies.map((name) => ({ name, delay: 24 })); },
      activeProfile: () => ({ id: "capacity" }), engineIsOff: () => true,
      controllerActionAllowed: () => true, captureEngineIdentityToken: () => null,
      engineIdentityTokenIsCurrent: () => true, appendLog: () => {}, renderPage: () => {},
      errorText: String, delayFailureLabel: String });
    await run();
    assert.equal(requests, 1);
    assert.match(state.proxyDelayMessage, /not tested: the two-minute test limit/u);
    assert.ok(nodes.some((node) => node.delay === 24));
    assert.ok(nodes.some((node) => node.delay === null && !node.delayFailure));
    assert.equal(state.toggles.testingDelays, false);
  } finally { globalThis.document = priorDocument; }
});
