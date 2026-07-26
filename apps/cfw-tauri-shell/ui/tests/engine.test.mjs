import assert from "node:assert/strict";
import test from "node:test";

import { engineStateLabel, normalizeEngineStatus, summarizeEngineEvent, tunnelValueLabel } from "../src/format.js";

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
  const engine = normalizeEngineStatus(proxyEnvelope());
  assert.equal(engine.mode, "system-proxy");
  assert.equal(engine.state, "ProxyActive");
  assert.equal(engine.active, true);
  assert.equal(engine.systemProxyActive, true);
  assert.equal(engine.tunnelAvailable, false);
  assert.equal(engineStateLabel(engine), "On");
  assert.equal(tunnelValueLabel(engine), "Off");
});

test("rejects active state with a mismatched generation, owner, digest or readiness", () => {
  const wrongGeneration = proxyEnvelope();
  wrongGeneration.snapshot.state.runtime.context.generation = 8;
  assert.throws(() => normalizeEngineStatus(wrongGeneration), /identity/u);

  const wrongOwner = proxyEnvelope();
  wrongOwner.snapshot.state.runtime.owner = "packet_tunnel_system_extension";
  assert.throws(() => normalizeEngineStatus(wrongOwner), /identity/u);

  const wrongDigest = proxyEnvelope();
  wrongDigest.snapshot.state.runtime.config_digest = "other";
  assert.throws(() => normalizeEngineStatus(wrongDigest), /identity/u);

  const notReady = proxyEnvelope();
  notReady.snapshot.state.runtime.ready = false;
  assert.throws(() => normalizeEngineStatus(notReady), /identity/u);
});

test("rejects a malformed envelope instead of assuming Off", () => {
  assert.throws(() => normalizeEngineStatus(null), /envelope/u);
  assert.throws(() => normalizeEngineStatus({}), /envelope/u);
  assert.throws(
    () => normalizeEngineStatus({ snapshot: { desired_mode: "off", generation: 0, state: { state: "nope" } } }),
    /state is invalid/u,
  );
  assert.throws(
    () => normalizeEngineStatus({ snapshot: { desired_mode: "off", generation: -1, state: { state: "off" } } }),
    /generation is invalid/u,
  );
  assert.throws(
    () => normalizeEngineStatus({ snapshot: { desired_mode: "script", generation: 0, state: { state: "off" } } }),
    /mode is invalid/u,
  );
});

test("keeps the fail-closed capability reason and the tunnel lifecycle labels", () => {
  const failed = normalizeEngineStatus({
    snapshot: {
      desired_mode: "tunnel",
      generation: 4,
      config_digest: null,
      state: { state: "failed", generation: 4, target: "tunnel", error: "signed Host Bridge is unavailable" },
    },
    capabilities: { system_proxy: false, tunnel: false },
    unavailable_reason: "native runtime unavailable",
  });
  assert.equal(failed.state, "Failed");
  assert.equal(failed.active, false);
  assert.equal(failed.tunnelAvailable, false);
  assert.equal(failed.availabilityReason, "signed Host Bridge is unavailable");
  assert.equal(tunnelValueLabel(failed), "Failed");

  const awaiting = normalizeEngineStatus({
    snapshot: {
      desired_mode: "tunnel",
      generation: 2,
      config_digest: null,
      state: { state: "awaiting_approval", generation: 2 },
    },
    capabilities: { system_proxy: true, tunnel: true },
  });
  assert.equal(awaiting.state, "AwaitingApproval");
  assert.equal(tunnelValueLabel(awaiting), "Needs approval");
  assert.equal(awaiting.availabilityReason, null);
});

test("redacts and bounds engine boundary failures before they reach the log pane", () => {
  const summary = summarizeEngineEvent({
    type: "boundary_failure",
    message: "https://example.test/path?token=query-secret Authorization: Bearer bearer-secret password=plain-secret",
  });
  assert.equal(summary.includes("query-secret"), false);
  assert.equal(summary.includes("bearer-secret"), false);
  assert.equal(summary.includes("plain-secret"), false);
  assert.match(summary, /\[redacted\]/u);
  assert.equal(summarizeEngineEvent({ type: "state", message: "x".repeat(4096) }).length, 2048);
  assert.equal(summarizeEngineEvent(null), "invalid engine event payload");
});
