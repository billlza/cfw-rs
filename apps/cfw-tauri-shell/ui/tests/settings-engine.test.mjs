// The engine status the dashboard reads: untrustworthy, unreadable or
// superseded reads, startup recovery, the controller version of a running
// engine, and when network switches are unavailable.
import { host, spy } from "./support/fake-host.mjs";
import { replaceEngineIdentity, runEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { test } from "node:test";
import { state, runtime } from "../src/state.js";
import { createEngineStatus } from "../src/engine-status.js";
import { engineToggleCapability, engineToggleChangeAllowed } from "../src/engine-capability.js";
import {
  lastLog, messages,
} from "./support/settings-engine-harness.mjs";

function engineStatus(overrides = {}) {
  const d = { renderPage: spy(), updateStatusBar: spy(), cancelDelayTest: spy(), ...overrides };
  return { d, status: createEngineStatus(d) };
}

const OFF_PAYLOAD = {
  snapshot: { desired_mode: "off", generation: 0, config_digest: null, state: { state: "off" } },
  capabilities: { system_proxy: true, tunnel: true, tunnel_system_proxy: true, provider_management: false },
  unavailable_reason: null,
};

const RECOVERABLE = {
  ...OFF_PAYLOAD,
  startup_recovery_available: true,
  snapshot: { desired_mode: "off", generation: 1, config_digest: null,
    state: { state: "failed", generation: 1, target: "off", error: "native service status unavailable" } },
};

test("an untrustworthy engine status is reported and treated as Off", async () => {
  const { status } = engineStatus();
  runEngine();
  status.applyEngineStatus({ snapshot: "garbage" });
  assert.equal(state.engine.active, false);
  assert.match(lastLog().message, /^Engine state could not be trusted/u);
  assert.match(state.engine.availabilityReason, /./u);
});

test("an unreadable engine status ends the engine-bound state and is reported", async () => {
  const { d, status } = engineStatus();
  runEngine();
  host.respond("engine_snapshot", new Error("service unreachable"));
  host.respond("geoip_database_status", new Error("database missing"));
  assert.equal(await status.loadEngineStatus(), true);
  assert.equal(state.engine.availabilityReason, "service unreachable");
  assert.equal(d.cancelDelayTest.count(), 1);
  assert.ok(messages().includes("Unable to read the engine state: service unreachable"));
  assert.ok(messages().includes("Unable to read the GeoIP database status: database missing"));
  assert.equal(state.geoipStatus, null);
});

test("a superseded engine status read is discarded", async () => {
  const { status } = engineStatus();
  host.respond("engine_snapshot", () => { runtime.engineStatusRequestId += 1; return OFF_PAYLOAD; });
  assert.equal(await status.loadEngineStatus(), false);
  host.respond("engine_snapshot", () => { runtime.engineStatusRequestId += 1; return new Error("late"); });
  state.logs = [];
  assert.equal(await status.loadEngineStatus(), false);
  assert.equal(state.logs.length, 0);
});

test("startup recovery is offered only while the host says a read can resolve it", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const { d, status } = engineStatus();
  runtime.startupRecovery.delays = [10, 10];
  runtime.startupRecovery.attempts = 0;
  runtime.startupRecovery.exhausted = false;
  runtime.startupRecovery.timer = null;
  host.respond("engine_snapshot", RECOVERABLE);
  host.respond("geoip_database_status", null);
  host.respond("reconcile_startup_services", { ...OFF_PAYLOAD, startup_recovery_available: false });
  await status.loadEngineStatus();
  assert.notEqual(runtime.startupRecovery.timer, null, "a retry is scheduled");
  state.migrationHandoff = true;
  status.applyEngineStatus(RECOVERABLE);
  assert.equal(runtime.startupRecovery.timer, null, "a handoff window never recovers by itself");
  state.migrationHandoff = false;
  status.applyEngineStatus(RECOVERABLE);
  t.mock.timers.tick(10);
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(host.argsOf("reconcile_startup_services").length, 1);
  assert.equal(runtime.startupRecovery.attempts, 0, "a recovered engine resets the attempts");
  assert.ok(d.renderPage.count() >= 1);
});

test("startup recovery is explicit, refused while busy or unavailable, and must prove the engine is Off", async () => {
  const { status } = engineStatus();
  state.engineMutationBusy = true;
  await assert.rejects(() => status.reconcileStartupServices(), /already in progress/u);
  state.engineMutationBusy = false;
  await assert.rejects(() => status.reconcileStartupServices(), /not available in the current state/u);
  host.respond("engine_snapshot", RECOVERABLE);
  host.respond("geoip_database_status", null);
  await status.loadEngineStatus();
  host.respond("reconcile_startup_services", { ...RECOVERABLE, snapshot: { ...RECOVERABLE.snapshot, desired_mode: "system_proxy" } });
  await assert.rejects(() => status.reconcileStartupServices(), /did not prove the engine is Off/u);
  assert.match(state.engineMutationError, /did not prove/u);
  assert.equal(state.engineMutationBusy, false);
  await status.loadEngineStatus();
  host.respond("reconcile_startup_services", OFF_PAYLOAD);
  await status.reconcileStartupServices();
  assert.equal(lastLog().message, "Background service recovery completed.");
  assert.equal(state.engine.startupRecoveryAvailable, false);
  await status.loadEngineStatus();
  host.respond("reconcile_startup_services", () => { runtime.engineStatusRequestId += 1; return OFF_PAYLOAD; });
  host.respond("engine_snapshot", OFF_PAYLOAD);
  await status.reconcileStartupServices();
  assert.equal(state.engine.startupRecoveryAvailable, false, "a superseded answer is replaced by a fresh read");
});

test("a failed automatic recovery attempt is logged and the page explains what is next", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const { d, status } = engineStatus();
  runtime.startupRecovery.delays = [5];
  runtime.startupRecovery.attempts = 0;
  runtime.startupRecovery.exhausted = false;
  runtime.startupRecovery.timer = null;
  host.respond("reconcile_startup_services", new Error("launchd busy"));
  host.respond("engine_snapshot", RECOVERABLE);
  host.respond("geoip_database_status", null);
  status.applyEngineStatus(RECOVERABLE);
  t.mock.timers.tick(5);
  for (let index = 0; index < 4; index += 1) await new Promise((resolve) => setImmediate(resolve));
  assert.ok(messages().includes("Automatic background service recovery did not succeed yet: launchd busy"));
  assert.equal(runtime.startupRecovery.exhausted, true, "after the last automatic attempt the user is asked");
  assert.ok(d.renderPage.count() >= 1);
});

test("a running engine's controller version is read for that engine only", async () => {
  const { status } = engineStatus();
  const RUNNING = {
    snapshot: { desired_mode: "system_proxy", generation: 3, config_digest: "digest",
      state: { state: "proxy_active", runtime: { owner: "proxy_agent", context: { installation_id: "i", config_epoch: 1, generation: 3 }, config_digest: "digest", ready: true } } },
    capabilities: { system_proxy: true, tunnel: true, tunnel_system_proxy: true, provider_management: false },
    unavailable_reason: null,
  };
  host.respond("engine_snapshot", RUNNING);
  host.respond("geoip_database_status", { state: "ready" });
  host.respond("controller_version", { version: "1.14.4" });
  await status.loadEngineStatus();
  assert.deepEqual(state.controllerVersion, { version: "1.14.4" });
  assert.ok(state.engineStartedAt > 0);
  host.respond("controller_version", new Error("controller down"));
  await status.loadEngineStatus();
  assert.equal(state.controllerVersion, null);
  assert.equal(lastLog().message, "Unable to read the controller version: controller down");
  host.respond("controller_version", () => { replaceEngineIdentity(); return new Error("late"); });
  assert.equal(await status.loadEngineStatus(), false);
  host.respond("engine_snapshot", OFF_PAYLOAD);
  await status.loadEngineStatus();
  assert.equal(state.controllerVersion, null);
  assert.equal(state.engineStartedAt, null);
});

test("network switches are unavailable in a handoff window and during startup recovery", () => {
  state.migrationHandoff = true;
  for (const key of ["coreRunning", "systemProxy", "tunMode"]) {
    assert.match(engineToggleCapability(key).reason, /owns legacy CFM maintenance/u);
  }
  assert.equal(engineToggleChangeAllowed("tunMode", false, "ui"), false, "even turning off is refused in a handoff window");
  assert.match(lastLog().message, /owns legacy CFM maintenance/u);
  state.migrationHandoff = false;
  state.engine = { ...state.engine, startupRecoveryAvailable: true };
  assert.deepEqual(["coreRunning", "systemProxy", "tunMode"].map((key) => engineToggleCapability(key).label), ["Core", "System Proxy", "TUN Mode"]);
  assert.match(engineToggleCapability("systemProxy").reason, /Recover background services/u);
  assert.equal(engineToggleCapability("silentStart"), null);
  assert.equal(engineToggleChangeAllowed("silentStart", true, "ui"), true);
  assert.equal(engineToggleChangeAllowed("tunMode", false, "ui"), true, "a requested mode can always be turned off");
});

test("the combined mode is refused with its own reason", () => {
  state.engine = { ...state.engine, desiredMode: "tunnel", systemProxyAvailable: true, tunnelAvailable: true, tunnelSystemProxyAvailable: false };
  assert.equal(engineToggleCapability("systemProxy").available, false);
  assert.match(engineToggleCapability("systemProxy").reason, /./u);
  state.engine = { ...state.engine, desiredMode: "system-proxy" };
  assert.equal(engineToggleCapability("tunMode").available, false);
  state.engine = { ...state.engine, tunnelSystemProxyAvailable: true };
  assert.equal(engineToggleCapability("tunMode").available, true);
  state.engine = { ...state.engine, localProxyAvailable: false, availabilityReason: null };
  assert.match(engineToggleCapability("coreRunning").reason, /./u);
});
