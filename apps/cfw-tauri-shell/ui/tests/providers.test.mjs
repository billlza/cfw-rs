import assert from "node:assert/strict";
import test from "node:test";
import { createProviderUI } from "../src/providers.js";

function fixture() {
  const state = { engine: { active: false, providerManagementAvailable: true }, profiles: [{ id: "A", active: true }],
    providers: [], ruleProviders: [], providerActions: new Set(), providerBulkActions: new Set() };
  const calls = [];
  const logs = [];
  const snapshot = { proxy_providers: [{ name: "Japan <script>", kind: "Proxy", vehicle_type: "HTTP", proxies: ["Tokyo"], extra: { updatable: true } }], rule_providers: [] };
  const responses = { providers_snapshot: snapshot, update_all_providers: { action: "update", requested: 1, succeeded: ["Japan"], failed: [] }, health_check_all_proxy_providers: { requested: 1, succeeded: ["Japan"], failed: [] } };
  const ui = createProviderUI({ state, invoke: async (command) => { calls.push(command); return await responses[command]; },
    appendLog: (...args) => logs.push(args), renderPage() {}, refreshProfile: async () => { state.engine.generation = 99; },
  });
  return { state, calls, logs, responses, ui };
}

test("Off profiles support health checks and one atomic bulk update", async () => {
  const { ui, calls, state } = fixture();
  await ui.loadProvidersSnapshot();
  const page = ui.renderProviders();
  assert.match(page, /Japan &lt;script&gt;/u);
  assert.doesNotMatch(page, /<script>/u);
  assert.match(page, /data-provider-update="Japan &lt;script&gt;" >Update/u);
  await ui.handleProviderAction("update-all-providers");
  await ui.handleProviderAction("health-check-all");
  assert.equal(calls.filter((command) => command === "update_all_providers").length, 1);
  assert.ok(calls.includes("health_check_all_proxy_providers"));
  assert.equal(state.providerBulkActions.size, 0);
  assert.equal(state.engine.active, false);
});

test("provider responses cannot cross profile selection, including A to B to A", async () => {
  const { ui, state, responses } = fixture();
  let finish;
  responses.providers_snapshot = new Promise((resolve) => { finish = resolve; });
  const pending = ui.loadProvidersSnapshot();
  state.profiles = [{ id: "B", active: true }]; ui.providerSelectionChanged();
  state.profiles = [{ id: "A", active: true }]; ui.providerSelectionChanged();
  finish({ proxy_providers: [{ name: "stale", proxies: [] }], rule_providers: [] });
  assert.equal(await pending, false);
  assert.deepEqual(state.providers, []);
});

test("provider failure is reported without inventing a controller outage", async () => {
  const { ui, state, responses, logs } = fixture();
  state.controllerStatus = "ready";
  // A rejected operation is consumed immediately by the invoked request.
  Object.defineProperty(responses, "update_all_providers", { get() { throw new Error("resource validation failed; old profile retained"); } });
  await ui.handleProviderAction("update-all-providers");
  assert.equal(state.controllerStatus, "ready");
  assert.ok(logs.some(([level, , message]) => level === "error" && message.includes("old profile retained")));
  assert.equal(state.providerBulkActions.size, 0);
});
