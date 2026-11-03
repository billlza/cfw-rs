// Reload and Engine Off: what a reload refreshes, and that nothing calls the
// controller while the core is off or after it stops.
import assert from "node:assert/strict";
import test from "node:test";
import {
  OFF_ENGINE, RUNNING_ENGINE, appModule, deferred, element, emit, interactiveElement,
  invocationDetails, invoked, page, querySelectorAllElements, querySelectorElements, rejected,
  reloadButton, renderPage, responses, setEngine, state, streamEvent, waitForInvocation,
} from "./support/render-harness.mjs";

test("global Reload refreshes the active projection and controller rules", async () => {
  const originalProjection = responses.read_runtime_config_text;
  const originalRules = responses.rules_snapshot;
  responses.read_runtime_config_text = JSON.stringify({
    log: { level: "debug" },
    experimental: { clash_api: { external_controller: "127.0.0.1:9091" } },
    inbounds: [{ type: "mixed", tag: "cfw-system-proxy", listen: "127.0.0.1", listen_port: 7891 }],
    outbounds: [{ type: "direct", tag: "direct" }],
  });
  responses.rules_snapshot = {
    rules: [{ index: 7, type: "DOMAIN", payload: "fresh.example", proxy: "Proxy", size: 1, hits: 2, provider: null, extra: {} }],
  };

  try {
    await renderPage("rules");
    await reloadButton.click();
    assert.equal(state.projection.mixedPort, 7891);
    assert.equal(state.projection.controller, "127.0.0.1:9091");
    assert.equal(state.projection.logLevel, "debug");
    assert.equal(state.rules.length, 1);
    assert.equal(state.rules[0].payload, "fresh.example");
    assert.match(page.innerHTML, /fresh\.example/u);
  } finally {
    responses.read_runtime_config_text = originalProjection;
    responses.rules_snapshot = originalRules;
  }
});

test("Engine Off reload never schedules controller-backed IPC or keeps a stale projection", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalRetirement = responses.legacy_retirement_status;
  const originalProfiles = responses.profiles_snapshot;
  const originalProjectionRejection = rejected.read_runtime_config_text;
  const originalPage = state.activePage;
  const originalLogsPaused = state.logsPaused;
  const originalConnectionPaused = state.connectionPaused;

  try {
    responses.engine_snapshot = OFF_ENGINE;
    responses.legacy_retirement_status = { state: "awaiting_confirmation" };
    responses.profiles_snapshot = { profiles: [], invalid_profiles: [] };
    rejected.read_runtime_config_text = "no active profile is selected";
    await emit("cfw://settings-changed", responses.read_settings_snapshot);
    await renderPage("rules");

    invoked.length = 0;
    invocationDetails.length = 0;
    const failureCount = state.logs.filter(({ level, source }) => (
      (level === "warning" || level === "error")
      && (source === "controller" || source === "provider" || source === "rules")
    )).length;

    await reloadButton.click();

    state.logsPaused = true;
    state.connectionPaused = true;
    state.profilesUnavailableReason = "profile repository unavailable";
    for (const action of [
      "update-all-providers",
      "health-check-all",
      "reload-rules",
      "flush-fake-ip-cache",
      "break-proxy-connections",
      "close-all",
      "toggle-log-stream",
      "toggle-connection-stream",
      "migrate-legacy-profiles",
    ]) {
      await appModule.handleAction(action);
    }

    for (const command of [
      "controller_snapshot",
      "providers_snapshot",
      "rules_snapshot",
      "start_connections_stream",
      "start_log_stream",
      "update_all_proxy_providers",
      "update_all_rule_providers",
      "health_check_all_proxy_providers",
      "flush_fake_ip_cache",
      "close_all_connections",
      "preview_legacy_cfw_profile_migration",
    ]) {
      assert.equal(invoked.includes(command), false, `${command} must not run while the engine is Off`);
    }
    assert.equal(state.controllerStatus, "engine off");
    assert.deepEqual(state.projection, {
      mixedPort: null,
      listenAddress: null,
      controller: null,
      logLevel: null,
      error: "no active profile is selected",
    });
    assert.equal(
      state.logs.filter(({ level, source }) => (
        (level === "warning" || level === "error")
        && (source === "controller" || source === "provider" || source === "rules")
      )).length,
      failureCount,
      "an expected Off state must not be logged as a controller failure",
    );

    const general = await renderPage("general");
    assert.match(general, /Automatic port/u);
    assert.match(general, /127\.0\.0\.1:7890/u, "configured port is readable without an active profile");
    assert.equal(state.projection.mixedPort, null, "configured preferences do not masquerade as a live profile projection");
  } finally {
    responses.engine_snapshot = originalEngine;
    responses.legacy_retirement_status = originalRetirement;
    responses.profiles_snapshot = originalProfiles;
    state.logsPaused = originalLogsPaused;
    state.connectionPaused = originalConnectionPaused;
    if (originalProjectionRejection === undefined) {
      delete rejected.read_runtime_config_text;
    } else {
      rejected.read_runtime_config_text = originalProjectionRejection;
    }
    await reloadButton.click();
    await renderPage(originalPage);
  }
});

test("Engine Off click handlers never invoke individual controller operations", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalDialog = state.glassDialog;
  const mode = interactiveElement();
  mode.dataset.mode = "Rule";
  const proxy = interactiveElement();
  proxy.dataset.group = "Proxy";
  proxy.dataset.node = "JP";
  const proxyProvider = interactiveElement();
  proxyProvider.dataset.providerUpdate = "proxy-provider";
  const ruleProvider = interactiveElement();
  ruleProvider.dataset.ruleProviderUpdate = "rule-provider";
  const health = interactiveElement();
  health.dataset.providerHealth = "proxy-provider";
  const close = interactiveElement();
  close.dataset.closeConnection = "c1";
  const dns = interactiveElement();
  const dnsName = element("input");
  dnsName.value = "example.com";
  const dnsType = element("input");
  dnsType.value = "A";

  try {
    await setEngine(OFF_ENGINE);
    state.proxyGroups = [{ name: "Proxy", now: "HK", options: [] }];
    state.connections = [{ id: "c1" }];
    state.glassDialog = { kind: "dns-query", payload: { name: "example.com", type: "A", result: "" } };
    querySelectorAllElements.set("[data-mode]", [mode]);
    querySelectorAllElements.set("[data-group][data-node]", [proxy]);
    querySelectorAllElements.set("[data-provider-update], [data-rule-provider-update]", [proxyProvider, ruleProvider]);
    querySelectorAllElements.set("[data-provider-health]", [health]);
    querySelectorAllElements.set("[data-close-connection]", [close]);
    querySelectorAllElements.set("[data-glass-dns-confirm]", [dns]);
    querySelectorElements.set("[data-glass-dns-name]", dnsName);
    querySelectorElements.set("[data-glass-dns-type]", dnsType);
    await renderPage("providers");
    invoked.length = 0;

    for (const button of [mode, proxy, proxyProvider, ruleProvider, health, close, dns]) {
      await button.trigger("click");
    }

    for (const command of [
      "set_proxy_mode",
      "select_proxy",
      "update_proxy_provider",
      "update_rule_provider",
      "health_check_proxy_provider",
      "close_connection",
      "dns_query",
    ]) {
      assert.equal(invoked.includes(command), false, `${command} must not run from an Off-state click`);
    }
  } finally {
    querySelectorElements.clear();
    querySelectorAllElements.clear();
    state.glassDialog = originalDialog;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("Engine Off invalidates a pending controller snapshot and live connection/log events", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const pendingController = deferred();
  let reloadPromise = null;

  try {
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    const previousCalls = invocationDetails.filter((entry) => entry.command === "controller_snapshot").length;
    responses.controller_snapshot = pendingController.promise;
    reloadPromise = reloadButton.click();
    await waitForInvocation("controller_snapshot", previousCalls);

    responses.engine_snapshot = OFF_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });

    assert.equal(state.controllerStatus, "engine off");
    assert.deepEqual(state.proxyGroups, []);
    assert.deepEqual(state.connections, []);
    assert.deepEqual(state.rules, []);
    assert.deepEqual(state.providers, []);
    assert.deepEqual(state.ruleProviders, []);
    assert.equal(state.connectionStream.uploadTotal, 0);
    assert.equal(state.connectionStream.downloadTotal, 0);
    assert.equal(state.traffic.upload, 0);
    assert.equal(state.traffic.download, 0);

    await emit(
      "cfw://connections-snapshot",
      streamEvent("connections", originalController.connections, RUNNING_ENGINE),
    );
    await emit("cfw://log-lines", streamEvent("request-logs", [{
        time: "12:00:01",
        level: "info",
        source: "stale-engine",
        message: "stale engine log must be ignored",
        fields: [],
      }], RUNNING_ENGINE));
    assert.deepEqual(state.connections, []);
    assert.equal(state.logs.some((entry) => entry.message === "stale engine log must be ignored"), false);

    pendingController.resolve({
      ...structuredClone(originalController),
      proxies: {
        groups: [{ name: "STALE", kind: "Selector", now: "STALE", options: ["STALE"], history: [] }],
        proxies: [],
      },
    });
    await reloadPromise;

    assert.deepEqual(state.proxyGroups, []);
    assert.deepEqual(state.connections, []);
    assert.deepEqual(state.rules, []);
    assert.equal(state.controllerStatus, "engine off");
  } finally {
    pendingController.resolve(originalController);
    if (reloadPromise) await reloadPromise.catch(() => {});
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("Provider metadata survives core Stop while live rule snapshots remain generation-bound", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalProviders = responses.providers_snapshot;
  const originalProviderRejection = rejected.providers_snapshot;
  const originalRules = responses.rules_snapshot;
  const hadProvidersResponse = Object.hasOwn(responses, "providers_snapshot");
  const hadProviderRejection = Object.hasOwn(rejected, "providers_snapshot");
  const pendingProviders = deferred();
  const pendingRules = deferred();
  let providerReload = null;
  let rulesReload = null;

  try {
    await setEngine({
      ...RUNNING_ENGINE,
      capabilities: { ...RUNNING_ENGINE.capabilities, provider_management: true },
    });
    delete rejected.providers_snapshot;
    responses.providers_snapshot = pendingProviders.promise;
    const providerCalls = invocationDetails.filter((entry) => entry.command === "providers_snapshot").length;
    providerReload = reloadButton.click();
    await waitForInvocation("providers_snapshot", providerCalls);

    responses.engine_snapshot = { ...OFF_ENGINE, capabilities: { ...OFF_ENGINE.capabilities, provider_management: true } };
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    pendingProviders.resolve({
      proxy_providers: [{ name: "SAVED-PROVIDER", kind: "Proxy", vehicle_type: "HTTP", proxies: [] }],
      rule_providers: [{ name: "SAVED-RULE-PROVIDER", kind: "Rule", vehicle_type: "HTTP", rules: [] }],
    });
    await providerReload;

    assert.deepEqual(state.providers.map(({ name }) => name), ["SAVED-PROVIDER"]);
    assert.deepEqual(state.ruleProviders.map(({ name }) => name), ["SAVED-RULE-PROVIDER"]);
    assert.equal(state.providerCapabilityError, null);

    if (hadProviderRejection) rejected.providers_snapshot = originalProviderRejection;
    else delete rejected.providers_snapshot;
    if (hadProvidersResponse) responses.providers_snapshot = originalProviders;
    else delete responses.providers_snapshot;
    await setEngine(RUNNING_ENGINE);
    await renderPage("rules");

    responses.rules_snapshot = pendingRules.promise;
    const ruleCalls = invocationDetails.filter((entry) => entry.command === "rules_snapshot").length;
    rulesReload = reloadButton.click();
    await waitForInvocation("rules_snapshot", ruleCalls);

    responses.engine_snapshot = OFF_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    pendingRules.resolve({
      rules: [{ index: 999, type: "DOMAIN", payload: "stale.example", proxy: "STALE" }],
    });
    await rulesReload;

    assert.deepEqual(state.rules, []);
    assert.equal(state.controllerStatus, "engine off");
  } finally {
    pendingProviders.resolve({ proxy_providers: [], rule_providers: [] });
    pendingRules.resolve({ rules: [] });
    if (providerReload) await providerReload.catch(() => {});
    if (rulesReload) await rulesReload.catch(() => {});
    if (hadProvidersResponse) responses.providers_snapshot = originalProviders;
    else delete responses.providers_snapshot;
    if (hadProviderRejection) rejected.providers_snapshot = originalProviderRejection;
    else delete rejected.providers_snapshot;
    responses.rules_snapshot = originalRules;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});
