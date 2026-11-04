// Turning network integration on and off: unavailable capabilities, a host
// without the combined mode, ordinary mode switches, refusals, and hand-off
// windows.
import assert from "node:assert/strict";
import test from "node:test";
import {
  OFF_ENGINE, WINDOWS_PLATFORM_DESIGN, appModule, dispatchDocumentEvent, interactiveElement,
  invocationDetails, invoked, page, querySelectorAllElements, rejected, reloadButton, renderPage,
  responses, runtime, setEngine, state,
} from "./support/render-harness.mjs";

test("unavailable network capabilities block every enable path but never trap an enabled request", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalSystemProxyResponse = responses.set_system_proxy_enabled;
  const originalTunResponse = responses.set_tun_enabled;
  const hadSystemProxyResponse = Object.hasOwn(responses, "set_system_proxy_enabled");
  const hadTunResponse = Object.hasOwn(responses, "set_tun_enabled");
  const unavailableReason = "replacement networking capability is unavailable";
  const cases = [
    {
      key: "systemProxy",
      command: "set_system_proxy_enabled",
      shortcut: "p",
      retry: "retry-system-proxy",
      cancel: "cancel-system-proxy",
      desiredMode: "system_proxy",
    },
    {
      key: "tunMode",
      command: "set_tun_enabled",
      shortcut: "t",
      retry: "retry-tun-mode",
      cancel: "cancel-tun-mode",
      desiredMode: "tunnel",
    },
  ];

  try {
    for (const [index, scenario] of cases.entries()) {
      const unavailableOff = {
        snapshot: {
          desired_mode: "off",
          generation: 20 + index * 2,
          config_digest: null,
          state: { state: "off" },
        },
        capabilities: { system_proxy: false, tunnel: false },
        unavailable_reason: unavailableReason,
      };
      const unavailableRequested = {
        snapshot: {
          desired_mode: scenario.desiredMode,
          generation: 21 + index * 2,
          config_digest: null,
          state: { state: "failed", error: unavailableReason },
        },
        capabilities: { system_proxy: false, tunnel: false },
        unavailable_reason: unavailableReason,
      };
      const input = interactiveElement("input");
      input.dataset.toggle = scenario.key;
      querySelectorAllElements.set("[data-toggle]", [input]);

      await setEngine(unavailableOff);
      const unavailableHtml = await renderPage("general");
      const unavailableInput = unavailableHtml.match(new RegExp(`<input type="checkbox" data-toggle="${scenario.key}"([^>]*)>`, "u"));
      assert.ok(unavailableInput, `${scenario.key} input must render`);
      assert.match(unavailableInput[1], /disabled/u);

      invoked.length = 0;
      invocationDetails.length = 0;
      input.checked = true;
      await input.trigger("change");
      assert.equal(invoked.includes(scenario.command), false, `${scenario.key} DOM enable must issue zero IPC`);

      await dispatchDocumentEvent("keydown", { key: scenario.shortcut, metaKey: true, ctrlKey: false, altKey: false });
      assert.equal(invoked.includes(scenario.command), false, `${scenario.key} shortcut enable must issue zero IPC`);

      await appModule.handleAction(scenario.retry);
      assert.equal(invoked.includes(scenario.command), false, `${scenario.key} retry enable must issue zero IPC`);

      if (scenario.key === "tunMode") {
        await setEngine({
          snapshot: {
            desired_mode: "tunnel",
            generation: 40,
            config_digest: null,
            state: { state: "awaiting_approval" },
          },
          capabilities: { system_proxy: false, tunnel: false },
          unavailable_reason: unavailableReason,
        });
        invoked.length = 0;
        invocationDetails.length = 0;
        await appModule.handleAction(scenario.retry);
        assert.equal(invoked.length, 0, "an unavailable approval retry must issue zero IPC of any kind");
      }

      await setEngine(unavailableRequested);
      responses[scenario.command] = OFF_ENGINE;
      const requestedHtml = await renderPage("general");
      const requestedInput = requestedHtml.match(new RegExp(`<input type="checkbox" data-toggle="${scenario.key}"([^>]*)>`, "u"));
      assert.ok(requestedInput, `${scenario.key} requested input must render`);
      assert.doesNotMatch(requestedInput[1], /checked/u, "a failed request is never displayed as active");
      assert.match(requestedInput[1], /disabled/u);
      assert.match(requestedHtml, new RegExp(`data-action="${scenario.cancel}">Cancel request`, "u"));

      invoked.length = 0;
      invocationDetails.length = 0;
      await appModule.handleAction(scenario.cancel);
      const disable = invocationDetails.find((entry) => entry.command === scenario.command);
      assert.ok(disable, `${scenario.key} disable must reach native admission`);
      assert.equal(disable.args.enabled, false);
    }
  } finally {
    querySelectorAllElements.clear();
    if (hadSystemProxyResponse) responses.set_system_proxy_enabled = originalSystemProxyResponse;
    else delete responses.set_system_proxy_enabled;
    if (hadTunResponse) responses.set_tun_enabled = originalTunResponse;
    else delete responses.set_tun_enabled;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("a host without the combined mode refuses the second integration with its own reason", async () => {
  const original = {
    product: state.payload.product, platform: state.platform, engine: responses.engine_snapshot,
    hadSystemProxy: Object.hasOwn(responses, "set_system_proxy_enabled"), systemProxy: responses.set_system_proxy_enabled,
    hadTun: Object.hasOwn(responses, "set_tun_enabled"), tun: responses.set_tun_enabled,
  };
  // Windows offers each integration on its own; the backend refuses the
  // combined mode, so the capability payload says so separately.
  const capabilities = { local_proxy: true, system_proxy: true, tunnel: true, tunnel_system_proxy: false, provider_management: false };
  const reason = "TUN Mode and System Proxy cannot run together in this Windows build. Turn one off first.";
  const offEngine = { snapshot: { desired_mode: "off", generation: 50, config_digest: null, state: { state: "off" } }, capabilities, unavailable_reason: null };
  const switchAttributes = (html, key) => {
    const match = html.match(new RegExp(`<input type="checkbox" data-toggle="${key}"([^>]*)>`, "u"));
    assert.ok(match, `${key} input must render`);
    return match[1];
  };
  try {
    state.payload.product = { ...original.product, name: "Clash for Windows", operating_system: "windows", architecture: "x64", minimum_os_version: null };
    state.platform = WINDOWS_PLATFORM_DESIGN;
    await setEngine(offEngine);
    const off = await renderPage("general");
    assert.doesNotMatch(switchAttributes(off, "systemProxy"), /disabled/u);
    assert.doesNotMatch(switchAttributes(off, "tunMode"), /disabled/u);
    assert.equal(off.includes(reason), false);
    for (const scenario of [
      { active: "systemProxy", activeCommand: "set_system_proxy_enabled", mode: "system_proxy", stateTag: "proxy_active",
        owner: "windows_user_agent", blocked: "tunMode", blockedCommand: "set_tun_enabled" },
      { active: "tunMode", activeCommand: "set_tun_enabled", mode: "tunnel", stateTag: "tunnel_active",
        owner: "windows_tunnel_service", blocked: "systemProxy", blockedCommand: "set_system_proxy_enabled" },
    ]) {
      await setEngine({
        snapshot: {
          desired_mode: scenario.mode, generation: 51, config_digest: "digest",
          state: { state: scenario.stateTag, runtime: { owner: scenario.owner, context: { installation_id: "i", config_epoch: 1, generation: 51 }, config_digest: "digest", ready: true } },
        },
        capabilities,
        unavailable_reason: null,
      });
      const html = await renderPage("general");
      assert.match(switchAttributes(html, scenario.blocked), /disabled/u, `${scenario.blocked} must be refused beside ${scenario.active}`);
      assert.doesNotMatch(switchAttributes(html, scenario.blocked), /checked/u);
      assert.match(switchAttributes(html, scenario.active), /checked/u);
      assert.doesNotMatch(switchAttributes(html, scenario.active), /disabled/u, `${scenario.active} must stay switchable off`);
      assert.ok(html.includes(reason), "the refusal names the combination, not a general failure");

      const blocked = interactiveElement("input");
      blocked.dataset.toggle = scenario.blocked;
      querySelectorAllElements.set("[data-toggle]", [blocked]);
      await renderPage("general");
      invoked.length = 0;
      invocationDetails.length = 0;
      blocked.checked = true;
      await blocked.trigger("change");
      assert.equal(invoked.includes(scenario.blockedCommand), false, `${scenario.blocked} enable must issue zero IPC`);

      // The requested integration is never trapped: turning it off still
      // reaches native admission.
      const active = interactiveElement("input");
      active.dataset.toggle = scenario.active;
      querySelectorAllElements.set("[data-toggle]", [active]);
      await renderPage("general");
      responses[scenario.activeCommand] = offEngine;
      invoked.length = 0;
      invocationDetails.length = 0;
      active.checked = false;
      await active.trigger("change");
      const disable = invocationDetails.find((entry) => entry.command === scenario.activeCommand);
      assert.ok(disable, `${scenario.active} disable must reach native admission`);
      assert.equal(disable.args.enabled, false);
      querySelectorAllElements.clear();
    }
    // A failed System Proxy request still holds the switch, and the TUN row
    // explains the combination, not the unrelated startup failure.
    await setEngine({
      snapshot: { desired_mode: "system_proxy", generation: 52, config_digest: null, state: { state: "failed", target: "system_proxy", error: "Earlier startup failed" } },
      capabilities,
      unavailable_reason: null,
    });
    const failed = await renderPage("general");
    assert.match(switchAttributes(failed, "tunMode"), /disabled/u);
    assert.ok(failed.includes(`title="${reason}"`), "the TUN row names the combination");
    assert.equal(failed.includes('title="Earlier startup failed"'), false);
  } finally {
    querySelectorAllElements.clear();
    if (original.hadSystemProxy) responses.set_system_proxy_enabled = original.systemProxy;
    else delete responses.set_system_proxy_enabled;
    if (original.hadTun) responses.set_tun_enabled = original.tun;
    else delete responses.set_tun_enabled;
    state.payload.product = original.product;
    state.platform = original.platform;
    responses.engine_snapshot = original.engine;
    await setEngine(original.engine);
    await reloadButton.click();
  }
});

test("normal mode switches call the existing backend without preparing or cleaning legacy data", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalRetirement = state.retirement;
  const originalHandoff = state.migrationHandoff;
  const originalMaintenance = state.legacyMaintenanceOpen;
  const originalError = state.engineMutationError;
  const originalCutover = structuredClone(state.cutover);
  const commands = ["set_system_proxy_enabled", "set_tun_enabled"];
  const originalResponses = new Map(commands.map((command) => [command, responses[command]]));
  const presentResponses = new Set(commands.filter((command) => Object.hasOwn(responses, command)));
  try {
    state.retirement = { state: "awaiting_confirmation" };
    state.migrationHandoff = false;
    state.legacyMaintenanceOpen = false;
    for (const [key, command, desired, status] of [
      ["systemProxy", "set_system_proxy_enabled", "system_proxy", "proxy_starting"],
      ["tunMode", "set_tun_enabled", "tunnel", "awaiting_approval"],
    ]) {
      await setEngine(OFF_ENGINE);
      const input = interactiveElement("input");
      input.dataset.toggle = key;
      querySelectorAllElements.set("[data-toggle]", [input]);
      const html = await renderPage("general");
      const rendered = html.match(new RegExp(`<input type="checkbox" data-toggle="${key}"([^>]*)>`, "u"));
      assert.ok(rendered);
      assert.doesNotMatch(rendered[1], /disabled/u);
      assert.doesNotMatch(html, /cfw-migration-banner|Start Migration|Prepare cutover|Finish setup/u);
      responses[command] = {
        snapshot: { desired_mode: desired, generation: 1, config_digest: null, state: { state: status, generation: 1 } },
        capabilities: { system_proxy: true, tunnel: true, tunnel_system_proxy: true },
        unavailable_reason: null,
      };
      invocationDetails.length = 0;
      input.checked = true;
      await input.trigger("change");
      assert.deepEqual(invocationDetails.filter((entry) => entry.command === command), [
        { command, args: { enabled: true } },
      ]);
      for (const forbidden of [
        "begin_migration_handoff", "prepare_legacy_cutover", "disable_service_mode",
        "recover_legacy_cutover", "reconcile_startup_services", "write_settings_snapshot", "reset_settings_snapshot",
      ]) {
        assert.equal(invocationDetails.some((entry) => entry.command === forbidden), false, forbidden);
      }
      assert.deepEqual(state.retirement, { state: "awaiting_confirmation" });
      assert.deepEqual(state.cutover, originalCutover);
      assert.equal(state.engine.active, false, "an accepted request is not proof of active networking");
    }
  } finally {
    querySelectorAllElements.clear();
    for (const command of commands) {
      if (presentResponses.has(command)) responses[command] = originalResponses.get(command);
      else delete responses[command];
    }
    state.retirement = originalRetirement;
    state.migrationHandoff = originalHandoff;
    state.legacyMaintenanceOpen = originalMaintenance;
    state.engineMutationError = originalError;
    await setEngine(originalEngine);
  }
});

test("a backend mode refusal remains visible while Off and is cleared by the next request", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalRetirement = state.retirement;
  const originalHandoff = state.migrationHandoff;
  const originalMaintenance = state.legacyMaintenanceOpen;
  const originalError = state.engineMutationError;
  const commands = ["set_system_proxy_enabled", "set_tun_enabled"];
  const originalResponses = new Map(commands.map((command) => [command, responses[command]]));
  const presentResponses = new Set(commands.filter((command) => Object.hasOwn(responses, command)));
  try {
    state.retirement = { state: "awaiting_confirmation" };
    state.migrationHandoff = false;
    state.legacyMaintenanceOpen = false;
    for (const [key, command, reason] of [
      ["systemProxy", "set_system_proxy_enabled", "A system proxy is already enabled; password=private-value"],
      ["tunMode", "set_tun_enabled", "The selected profile credential is missing"],
    ]) {
      await setEngine(OFF_ENGINE);
      const input = interactiveElement("input");
      input.dataset.toggle = key;
      querySelectorAllElements.set("[data-toggle]", [input]);
      await renderPage("general");
      rejected[command] = reason;
      input.checked = true;
      await input.trigger("change");
      assert.equal(state.engine.state, "Off");
      assert.equal(state.engine.active, false);
      assert.ok(page.innerHTML.includes(reason.split(";")[0]));
      assert.doesNotMatch(page.innerHTML, /private-value|Start Migration|Prepare cutover/u);
      assert.ok(state.engineMutationError.length <= 512);
      delete rejected[command];
      responses[command] = OFF_ENGINE;
      await renderPage("general");
      input.checked = true;
      await input.trigger("change");
      assert.equal(state.engineMutationError, null);
      assert.equal(page.innerHTML.includes(reason.split(";")[0]), false);
    }
  } finally {
    querySelectorAllElements.clear();
    for (const command of commands) {
      delete rejected[command];
      if (presentResponses.has(command)) responses[command] = originalResponses.get(command);
      else delete responses[command];
    }
    state.retirement = originalRetirement;
    state.migrationHandoff = originalHandoff;
    state.legacyMaintenanceOpen = originalMaintenance;
    state.engineMutationError = originalError;
    await setEngine(originalEngine);
  }
});

test("handoff windows keep ordinary mode mutations outside their command authority", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalRetirement = state.retirement;
  const originalHandoff = state.migrationHandoff;
  try {
    state.migrationHandoff = true;
    state.retirement = { state: "awaiting_confirmation" };
    await setEngine(OFF_ENGINE);
    for (const key of ["systemProxy", "tunMode"]) {
      const input = interactiveElement("input");
      input.dataset.toggle = key;
      querySelectorAllElements.set("[data-toggle]", [input]);
      const html = await renderPage("general");
      const rendered = html.match(new RegExp(`<input type="checkbox" data-toggle="${key}"([^>]*)>`, "u"));
      assert.match(rendered[1], /disabled/u);
      invocationDetails.length = 0;
      for (const checked of [true, false]) {
        input.checked = checked;
        await input.trigger("change");
      }
      assert.deepEqual(invocationDetails, []);
    }
  } finally {
    querySelectorAllElements.clear();
    state.retirement = originalRetirement;
    state.migrationHandoff = originalHandoff;
    await setEngine(originalEngine);
  }
});

test("proxy modes stay discoverable while Off and emit no controller mutation", async () => {
  const originalEngine = responses.engine_snapshot;
  const modeMutationsBefore = invocationDetails.filter(
    (entry) => entry.command === "set_proxy_mode",
  ).length;
  const directMode = interactiveElement();
  directMode.dataset.mode = "Direct";
  try {
    await setEngine(OFF_ENGINE);
    await reloadButton.click();
    querySelectorAllElements.set("[data-mode]", [directMode]);
    const html = await renderPage("proxies");
    for (const mode of ["Global", "Rule", "Direct"]) {
      const button = html.match(new RegExp(`<button class="[^"]*" data-mode="${mode}"([^>]*)>`, "u"));
      assert.ok(button, `${mode} must remain discoverable while the engine is Off`);
      assert.match(button[1], /disabled/u);
    }
    assert.doesNotMatch(html, /class="selected" data-mode=/u);
    await directMode.trigger("click");
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "set_proxy_mode").length,
      modeMutationsBefore,
    );
  } finally {
    querySelectorAllElements.clear();
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});
