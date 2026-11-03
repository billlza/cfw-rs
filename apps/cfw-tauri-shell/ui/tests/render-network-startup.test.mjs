// Network switches around startup: pending or failed starts, startup service
// recovery, the TUN approval row, a missed observation, and unknown switches.
import assert from "node:assert/strict";
import test from "node:test";
import { getLocale, setLocale } from "../src/i18n.js";
import {
  OFF_ENGINE, RUNNING_ENGINE, appModule, deferred, emit, interactiveElement, invocationDetails,
  querySelectorAllElements, renderPage, responses, runtime, setEngine, state, waitForInvocation,
} from "./support/render-harness.mjs";

test("network switches remain off while startup is pending or fails and cancellation remains available", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalProxyResponse = responses.set_system_proxy_enabled;
  const originalTunnelResponse = responses.set_tun_enabled;
  try {
    for (const [key, mode, command, retry, cancel] of [
      ["systemProxy", "system_proxy", "set_system_proxy_enabled", "retry-system-proxy", "cancel-system-proxy"],
      ["tunMode", "tunnel", "set_tun_enabled", "retry-tun-mode", "cancel-tun-mode"],
    ]) {
      await setEngine(OFF_ENGINE);
      const pending = deferred();
      responses[command] = () => pending.promise;
      const before = invocationDetails.filter((entry) => entry.command === command).length;
      const operation = appModule.handleAction(retry);
      await waitForInvocation(command, before);
      const starting = await renderPage("general");
      assert.doesNotMatch(starting, new RegExp(`data-toggle="${key}" checked`, "u"));
      assert.match(starting, new RegExp(`data-toggle="${key}"\\s+disabled`, "u"));
      pending.resolve({
        snapshot: { desired_mode: mode, generation: 200, config_digest: null, state: { state: "failed", target: mode, error: "native startup failed" } },
        capabilities: { system_proxy: true, tunnel: true, tunnel_system_proxy: true },
      });
      await operation;
      const failed = await renderPage("general");
      assert.doesNotMatch(failed, new RegExp(`data-toggle="${key}" checked`, "u"));
      assert.match(failed, /native startup failed/u);
      assert.match(failed, new RegExp(`data-action="${cancel}">Cancel request`, "u"));
      responses[command] = OFF_ENGINE;
      await appModule.handleAction(cancel);
      assert.equal(invocationDetails.filter((entry) => entry.command === command).at(-1).args.enabled, false);
      assert.equal(state.engine.desiredMode, "off");
    }
    await setEngine(RUNNING_ENGINE);
    assert.match(await renderPage("general"), /data-toggle="systemProxy" checked/u);
  } finally {
    if (originalProxyResponse === undefined) delete responses.set_system_proxy_enabled;
    else responses.set_system_proxy_enabled = originalProxyResponse;
    if (originalTunnelResponse === undefined) delete responses.set_tun_enabled;
    else responses.set_tun_enabled = originalTunnelResponse;
    await setEngine(originalEngine);
  }
});

test("engine status events do not discard a pending switch failure", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalResponse = responses.set_system_proxy_enabled;
  const originalError = state.engineMutationError;
  const failure = {
    snapshot: { desired_mode: "system_proxy", generation: 201, config_digest: null, state: { state: "failed", target: "system_proxy", error: "Earlier startup failed" } },
    capabilities: { system_proxy: true, tunnel: true, tunnel_system_proxy: true },
  };
  try {
    await setEngine(OFF_ENGINE);
    const pending = deferred();
    responses.set_system_proxy_enabled = () => pending.promise;
    const before = invocationDetails.filter(({ command }) => command === "set_system_proxy_enabled").length;
    const operation = appModule.handleAction("retry-system-proxy");
    const rejection = assert.rejects(operation, /Current startup failure/u);
    await waitForInvocation("set_system_proxy_enabled", before);
    responses.engine_snapshot = failure;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    pending.reject(new Error("Current startup failure"));
    await rejection;
    assert.equal(state.engineMutationBusy, false);
    assert.match(await renderPage("general"), /Current startup failure/u);
    assert.doesNotMatch(await renderPage("general"), /Earlier startup failed/u);
  } finally {
    if (originalResponse === undefined) delete responses.set_system_proxy_enabled;
    else responses.set_system_proxy_enabled = originalResponse;
    state.engineMutationError = originalError;
    await setEngine(originalEngine);
  }
});

test("startup service recovery is explicit, bounded to one request and stays Off", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalError = state.engineMutationError;
  const originalHandoff = state.migrationHandoff;
  const failure = {
    ...OFF_ENGINE,
    snapshot: { desired_mode: "off", generation: 0, config_digest: null,
      state: { state: "failed", target: "off", generation: 0, error: "Background service update failed" } },
    startup_recovery_available: true,
  };
  try {
    await setEngine(failure);
    const before = invocationDetails.length;
    const html = await renderPage("general");
    assert.match(html, /data-action="reconcile-startup-services"/u);
    assert.doesNotMatch(html, /data-action="toggle-core"/u);
    assert.equal(invocationDetails.slice(before).some(({ command }) => command === "reconcile_startup_services"), false);
    const pending = deferred();
    responses.reconcile_startup_services = () => pending.promise;
    const operation = appModule.handleAction("reconcile-startup-services");
    await waitForInvocation("reconcile_startup_services");
    assert.equal(state.engineMutationBusy, true);
    await assert.rejects(appModule.handleAction("reconcile-startup-services"), /in progress/u);
    assert.equal(invocationDetails.slice(before).filter(({ command }) => command === "reconcile_startup_services").length, 1);
    pending.resolve(OFF_ENGINE);
    await operation;
    assert.equal(state.engine.state, "Off");
    assert.equal(state.engineMutationBusy, false);
    assert.equal(invocationDetails.slice(before).some(({ command }) => /^(set_core_enabled|set_system_proxy_enabled|set_tun_enabled)$/u.test(command)), false);
    assert.doesNotMatch(await renderPage("general"), /data-action="reconcile-startup-services"/u);

    await setEngine(failure);
    responses.reconcile_startup_services = () => { throw new Error("Service recovery remains unproven"); };
    await assert.rejects(appModule.handleAction("reconcile-startup-services"), /remains unproven/u);
    assert.equal(state.engine.state, "Failed");
    assert.equal(state.engineMutationBusy, false);
    assert.match(await renderPage("general"), /Service recovery remains unproven/u);
    assert.match(await renderPage("general"), /data-action="reconcile-startup-services"/u);
    responses.reconcile_startup_services = () => RUNNING_ENGINE;
    await assert.rejects(appModule.handleAction("reconcile-startup-services"), /did not prove/u);
    assert.equal(state.engine.state, "Failed");
    assert.equal(state.engine.active, false);
    await setEngine({ ...failure, startup_recovery_available: false });
    assert.doesNotMatch(await renderPage("general"), /data-action="reconcile-startup-services"/u);
    const calls = invocationDetails.length;
    await assert.rejects(appModule.handleAction("reconcile-startup-services"), /not available/u);
    assert.equal(invocationDetails.length, calls);
    await setEngine(failure);
    state.migrationHandoff = true;
    assert.doesNotMatch(await renderPage("general"), /data-action="reconcile-startup-services"/u);
    const handoffCalls = invocationDetails.length;
    await assert.rejects(appModule.handleAction("reconcile-startup-services"), /not available/u);
    assert.equal(invocationDetails.length, handoffCalls);
  } finally {
    delete responses.reconcile_startup_services;
    state.engineMutationError = originalError;
    state.migrationHandoff = originalHandoff;
    await setEngine(originalEngine);
  }
});

test("startup recovery is asked for by the dashboard itself after an installation and then explained", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalError = state.engineMutationError;
  const failure = {
    ...OFF_ENGINE,
    snapshot: { desired_mode: "off", generation: 0, config_digest: null,
      state: { state: "failed", target: "off", generation: 0, error: "CleanupUnproven: Global cleanup could not be proven." } },
    startup_recovery_available: true,
  };
  const settle = async (predicate, label) => {
    for (let waited = 0; waited < 2000; waited += 10) {
      if (predicate()) return;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(`timed out waiting for ${label}`);
  };
  try {
    runtime.startupRecovery.delays = [80, 80];
    runtime.startupRecovery.attempts = 0;
    runtime.startupRecovery.exhausted = false;
    let calls = 0;
    responses.reconcile_startup_services = () => {
      calls += 1;
      if (calls === 1) throw new Error("services still restarting");
      return OFF_ENGINE;
    };
    await setEngine(failure);
    const waiting = await renderPage("general");
    assert.match(waiting, /Background services are restarting/u);
    assert.match(waiting, /Global cleanup could not be proven/u, "the host's reason stays as technical detail");
    assert.doesNotMatch(waiting, /Background services need your help/u);
    await settle(() => calls === 2 && state.engine.state === "Off", "the second automatic attempt");
    assert.equal(runtime.startupRecovery.attempts, 0, "a recovered engine ends and forgets the attempts");
    assert.equal(runtime.startupRecovery.exhausted, false);
    assert.doesNotMatch(await renderPage("general"), /data-action="reconcile-startup-services"/u);

    // The host keeps refusing: after the last automatic attempt the page
    // tells the user what to do, with the recovery button still there.
    calls = 0;
    responses.reconcile_startup_services = () => { calls += 1; throw new Error("services never came back"); };
    await setEngine(failure);
    assert.equal(runtime.startupRecovery.attempts, 1, "a fresh failure schedules the first attempt again");
    assert.match(await renderPage("general"), /Background services are restarting/u);
    await settle(() => runtime.startupRecovery.exhausted, "the attempts to be exhausted");
    assert.equal(calls, 2);
    const explained = await renderPage("general");
    assert.match(explained, /Background services need your help/u);
    assert.match(explained, /Login Items/u);
    assert.match(explained, /data-action="reconcile-startup-services"/u);
    assert.match(explained, /services never came back/u);

    // A recovery the user asks for while the attempts are exhausted still works.
    responses.reconcile_startup_services = () => OFF_ENGINE;
    await appModule.handleAction("reconcile-startup-services");
    assert.equal(state.engine.state, "Off");
    assert.equal(runtime.startupRecovery.exhausted, false);
    assert.equal(runtime.startupRecovery.attempts, 0);
  } finally {
    runtime.startupRecovery.delays = [];
    runtime.startupRecovery.attempts = 0;
    runtime.startupRecovery.exhausted = false;
    delete responses.reconcile_startup_services;
    state.engineMutationError = originalError;
    await setEngine(originalEngine);
  }
});

test("the TUN row says the start continues once the extension is allowed", async () => {
  const originalEngine = responses.engine_snapshot;
  const priorLocale = getLocale();
  const capabilities = { system_proxy: true, tunnel: true, tunnel_system_proxy: true };
  try {
    await setEngine({
      snapshot: { desired_mode: "tunnel", generation: 1, config_digest: null, state: { state: "awaiting_approval", generation: 1 } },
      capabilities,
    });
    // The note follows the Approve and Cancel buttons of the TUN row; the
    // short line is visible and the full instruction is its title.
    const note = /data-action="retry-tun-mode">Approve…<\/button>\s*<button class="cfw-text-button" data-action="cancel-tun-mode">Cancel request<\/button>\s*<small class="cfw-row-note" title="Allow the extension under System Settings › General › Login Items &amp; Extensions and the start continues by itself\. If it does not, click Approve… again\.">Continues once allowed<\/small>/u;
    assert.match(await renderPage("general"), note);

    setLocale("zh-Hans");
    assert.match(await renderPage("general"), /<small class="cfw-row-note" title="在「系统设置 › 通用 › 登录项与扩展」中允许扩展后，启动会自动继续。如果没有继续，再点一次「批准…」。">允许后自动继续<\/small>/u);
    setLocale(priorLocale);

    // No other tunnel state carries the note, a failed start included.
    for (const [generation, state] of [[2, "tunnel_installing"], [3, "tunnel_starting"], [4, "tunnel_active"]]) {
      await setEngine({ snapshot: { desired_mode: "tunnel", generation, config_digest: "digest", state: { state, generation } }, capabilities });
      assert.doesNotMatch(await renderPage("general"), /Continues once allowed/u, state);
    }
    await setEngine({
      snapshot: { desired_mode: "tunnel", generation: 5, config_digest: "digest", state: { state: "failed", generation: 5, target: "tunnel", error: "extension refused" } },
      capabilities,
    });
    const failed = await renderPage("general");
    assert.match(failed, /data-action="retry-tun-mode">Retry</u);
    assert.doesNotMatch(failed, /Continues once allowed/u);
  } finally {
    setLocale(priorLocale);
    await setEngine(originalEngine);
  }
});

test("a missed observation of a leased core is explained as a recheck instead of a failure", async () => {
  const reason = "native operation query_status failed: Timeout: query_status exceeded 2s";
  const failure = (recheckPending) => ({
    ...OFF_ENGINE,
    snapshot: { desired_mode: "local_proxy", generation: 7, config_digest: null,
      state: { state: "failed", target: "local_proxy", generation: 7, error: reason, recheck_pending: recheckPending } },
  });
  try {
    await setEngine(failure(true));
    assert.equal(state.engine.observationRecheckPending, true);
    const rechecking = await renderPage("general");
    assert.match(rechecking, /Confirming the core/u);
    assert.match(rechecking, /left as they are/u);
    assert.match(rechecking, /query_status exceeded 2s/u, "the host's reason stays as technical detail");
    assert.match(rechecking, /sing-box · Reconfirming…/u);
    assert.doesNotMatch(rechecking, /Background services/u);
    assert.doesNotMatch(rechecking, /sing-box · Failed/u);

    await setEngine(failure(false));
    assert.equal(state.engine.observationRecheckPending, false);
    const failed = await renderPage("general");
    assert.doesNotMatch(failed, /Confirming the core/u);
    assert.match(failed, /query_status exceeded 2s/u);
    assert.match(failed, /sing-box · Failed/u);
  } finally {
    await setEngine(OFF_ENGINE);
  }
});

test("an unknown switch is refused instead of reporting a saved change", async () => {
  await setEngine(RUNNING_ENGINE);
  const before = structuredClone(state.toggles);
  for (const key of ["notAToggle", "mixin"]) {
    const input = interactiveElement("input");
    input.dataset.toggle = key;
    querySelectorAllElements.set("[data-toggle]", [input]);
    await renderPage("settings");
    invocationDetails.length = 0;
    const refusals = () => state.logs.filter((entry) => entry.level === "error" && entry.message.startsWith(`${key} refused`)).length;
    const previousRefusals = refusals();
    input.checked = true;
    await input.trigger("change");
    assert.equal(invocationDetails.some((entry) => entry.command.startsWith("write_")), false, key);
    assert.equal(state.toggles[key], before[key], key);
    assert.equal(refusals(), previousRefusals + 1, key);
  }
  querySelectorAllElements.delete("[data-toggle]");
});
