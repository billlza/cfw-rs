import assert from "node:assert/strict";
import test from "node:test";

import { normalizeEngineEnvelope, normalizeRetirementStatus } from "../src/engine.js";

function proxyEnvelope(overrides = {}) {
  return {
    snapshot: {
      desired_mode: "system_proxy",
      generation: 9,
      config_digest: "abc123",
      state: {
        state: "proxy_active",
        runtime: {
          owner: "proxy_agent",
          context: { generation: 9 },
          config_digest: "abc123",
          ready: true,
        },
      },
    },
    capabilities: { system_proxy: true, tunnel: false },
    unavailable_reason: "Packet Tunnel is not linked",
    ...overrides,
  };
}

test("accepts an identity-bound active proxy snapshot", () => {
  const state = normalizeEngineEnvelope(proxyEnvelope());
  assert.equal(state.mode, "system-proxy");
  assert.equal(state.state, "ProxyActive");
  assert.equal(state.systemProxyActive, true);
  assert.equal(state.tunnelAvailable, false);
});

test("rejects active state with a mismatched generation or owner", () => {
  const wrongGeneration = proxyEnvelope();
  wrongGeneration.snapshot.state.runtime.context.generation = 8;
  assert.throws(() => normalizeEngineEnvelope(wrongGeneration), /identity/u);

  const wrongOwner = proxyEnvelope();
  wrongOwner.snapshot.state.runtime.owner = "packet_tunnel_system_extension";
  assert.throws(() => normalizeEngineEnvelope(wrongOwner), /identity/u);
});

test("preserves fail-closed native capability and failure reasons", () => {
  const state = normalizeEngineEnvelope({
    snapshot: {
      desired_mode: "tunnel",
      generation: 4,
      config_digest: null,
      state: { state: "failed", generation: 4, target: "tunnel", error: "signed Host Bridge is unavailable" },
    },
    capabilities: { system_proxy: false, tunnel: false },
    cutover_ready: false,
    cutover_unavailable_reason: "credential vault preflight unavailable",
    unavailable_reason: "native runtime unavailable",
  });
  assert.equal(state.state, "Failed");
  assert.equal(state.tunnelAvailable, false);
  assert.equal(state.tunnelReason, "signed Host Bridge is unavailable");
  assert.equal(state.cutoverReady, false);
  assert.equal(state.cutoverReason, "credential vault preflight unavailable");
});

test("requires explicit legacy retirement states", () => {
  assert.deepEqual(normalizeRetirementStatus({ state: "cleared" }), {
    state: "cleared",
    action: null,
    message: "Legacy network service is fully retired.",
  });
  assert.deepEqual(normalizeRetirementStatus({ state: "awaiting_confirmation" }), {
    state: "awaiting_confirmation",
    action: null,
    message: "The existing VPN remains untouched. Stage and select a replacement profile; cutover stays blocked until the signed native replacement passes preflight and you explicitly confirm.",
  });
  assert.deepEqual(normalizeRetirementStatus({ state: "cleaning" }), {
    state: "cleaning",
    action: null,
    message: "The explicitly confirmed one-way legacy network cutover is running.",
  });
  assert.deepEqual(
    normalizeRetirementStatus({
      state: "manual_cleanup_required",
      action: "review_dns",
      message: "Review DNS",
    }),
    { state: "manual_cleanup_required", action: "review_dns", message: "Review DNS" },
  );
  assert.throws(
    () => normalizeRetirementStatus({
      state: "manual_cleanup_required",
      action: "unexpected",
      message: "Review DNS",
    }),
    /invalid/u,
  );
  assert.throws(() => normalizeRetirementStatus({ state: "unknown" }), /invalid/u);
});
