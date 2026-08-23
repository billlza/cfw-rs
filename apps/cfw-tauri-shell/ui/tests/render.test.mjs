// Renders the restored dashboard against a minimal DOM and a canned IPC surface.
//
// The dashboard is a single self-bootstrapping module, exactly as in 0.3.5, so
// this file stubs what a WebView provides, drives the real bootstrap, and then
// renders every page, every dialog, and the engine states that change what the
// General page is allowed to claim. A render-time crash or a missing reason
// therefore fails in CI instead of in the app.
import assert from "node:assert/strict";
import test from "node:test";

const listeners = new Map();
const callbacks = new Map();
const querySelectorElements = new Map();
const querySelectorAllElements = new Map();
const documentListeners = new Map();
let nextCallbackId = 1;
let updateListenerWasReady = false;

function element(tag = "div", id = "") {
  return {
    tagName: tag.toUpperCase(),
    id,
    dataset: {},
    style: { setProperty() {}, width: "" },
    classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
    children: [],
    hidden: false,
    value: "",
    checked: false,
    disabled: false,
    textContent: "",
    innerHTML: "",
    scrollTop: 0,
    scrollHeight: 0,
    clientHeight: 0,
    files: [],
    addEventListener() {},
    removeEventListener() {},
    getBoundingClientRect: () => ({ top: 0, bottom: 100, left: 0, right: 100, width: 100, height: 100 }),
    querySelector: () => null,
    querySelectorAll: () => [],
    getAttribute: () => null,
    setAttribute() {},
    appendChild() {},
    insertBefore() {},
    insertAdjacentHTML() {},
    remove() {},
    closest: () => null,
    focus() {},
    blur() {},
    setSelectionRange() {},
    click() {},
    scrollIntoView() {},
    firstElementChild: null,
  };
}

const page = element("section", "page");
page.querySelector = (selector) => (
  selector === ".cfw-migration-banner" && page.innerHTML.includes("cfw-migration-banner")
    ? element("div")
    : null
);
const glassRoot = element("div", "glass-menu-root");
const reloadButton = element("button", "reload-button");
const reloadButtonListeners = new Map();
reloadButton.addEventListener = (type, listener) => reloadButtonListeners.set(type, listener);
reloadButton.click = async () => reloadButtonListeners.get("click")?.();
const documentStub = {
  documentElement: element("html"),
  body: element("body"),
  title: "",
  hidden: false,
  getElementById: (id) => {
    if (id === "page") return page;
    if (id === "glass-menu-root") return glassRoot;
    if (id === "reload-button") return reloadButton;
    return element("div", id);
  },
  querySelector: (selector) => querySelectorElements.get(selector) ?? null,
  querySelectorAll: (selector) => querySelectorAllElements.get(selector) ?? [],
  createElement: (tag) => element(tag),
  createDocumentFragment: () => ({ childNodes: [], appendChild() {} }),
  addEventListener(type, listener) {
    const handlers = documentListeners.get(type) ?? [];
    handlers.push(listener);
    documentListeners.set(type, handlers);
  },
};

globalThis.document = documentStub;
globalThis.window = {
  document: documentStub,
  innerWidth: 900,
  innerHeight: 700,
  requestAnimationFrame: (callback) => {
    callback();
    return 1;
  },
  setTimeout: (callback, delay) => setTimeout(callback, delay),
  setInterval: () => 1,
  matchMedia: () => ({ matches: false }),
};
globalThis.requestAnimationFrame = globalThis.window.requestAnimationFrame;
Object.defineProperty(globalThis, "navigator", {
  value: { hardwareConcurrency: 8, clipboard: { writeText: async () => {}, readText: async () => "" } },
  configurable: true,
});
globalThis.HTMLTextAreaElement = class {};
globalThis.HTMLInputElement = class {};
globalThis.HTMLSelectElement = class {};
globalThis.CSS = { escape: (value) => value };

const PROFILE_ID = "34db18b6-9903-4e9f-8854-15648e19e4f3";
const PROJECTION = JSON.stringify({
  log: { level: "info" },
  experimental: { clash_api: { external_controller: "127.0.0.1:9090", secret: "[REDACTED]" } },
  inbounds: [{ type: "mixed", tag: "cfw-system-proxy", listen: "127.0.0.1", listen_port: 7890 }],
  outbounds: [{ type: "direct", tag: "direct" }],
});

const RUNNING_ENGINE = {
  snapshot: {
    desired_mode: "system_proxy",
    generation: 3,
    config_digest: "digest",
    state: {
      state: "proxy_active",
      runtime: {
        owner: "proxy_agent",
        context: { installation_id: "i", config_epoch: 1, generation: 3 },
        config_digest: "digest",
        ready: true,
      },
    },
  },
  capabilities: { system_proxy: true, tunnel: true, provider_management: false },
  cutover_ready: true,
  cutover_unavailable_reason: null,
  unavailable_reason: null,
};

const OFF_ENGINE = {
  snapshot: { desired_mode: "off", generation: 0, config_digest: null, state: { state: "off" } },
  capabilities: { system_proxy: true, tunnel: true, provider_management: false },
  unavailable_reason: null,
};

let nextStreamId = 1;
const activeStreamBindings = new Map();
const latestStreamBindingsByIdentity = new Map();

function streamIdentityKey(stream, runtimeIdentity) {
  return `${stream}:${JSON.stringify(runtimeIdentity)}`;
}

function sameStreamBinding(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function startStreamFixture(stream, envelope = responses.engine_snapshot) {
  const runtimeIdentity = envelope?.snapshot?.state?.runtime;
  assert.ok(runtimeIdentity, `${stream} requires an active runtime fixture`);
  const active = activeStreamBindings.get(stream);
  if (active && sameStreamBinding(active.runtime, runtimeIdentity)) {
    return structuredClone(active);
  }
  const binding = {
    stream,
    stream_id: nextStreamId,
    runtime: structuredClone(runtimeIdentity),
  };
  nextStreamId += 1;
  activeStreamBindings.set(stream, binding);
  latestStreamBindingsByIdentity.set(streamIdentityKey(stream, runtimeIdentity), binding);
  return structuredClone(binding);
}

function stopStreamFixture({ expected }) {
  const active = activeStreamBindings.get(expected?.stream);
  if (active && sameStreamBinding(active, expected)) {
    activeStreamBindings.delete(expected.stream);
  }
  return null;
}

function streamBindingFor(stream, envelope = responses.engine_snapshot) {
  const runtimeIdentity = envelope?.snapshot?.state?.runtime;
  assert.ok(runtimeIdentity, `${stream} requires an active runtime fixture`);
  const binding = latestStreamBindingsByIdentity.get(streamIdentityKey(stream, runtimeIdentity));
  assert.ok(binding, `${stream} fixture has not been started for this runtime`);
  return structuredClone(binding);
}

function streamEvent(stream, payload, envelope = responses.engine_snapshot) {
  return {
    provenance: streamBindingFor(stream, envelope),
    payload,
  };
}

const DIAGNOSTICS = {
  default_route_interface: null,
  service_order: ["Wi-Fi"],
  services: [{
    service_id: "S1",
    display_name: "Wi-Fi",
    order: 0,
    web: { enabled: true, server: "127.0.0.1", port: 7890 },
    secure_web: { enabled: false, server: null, port: null },
    socks: { enabled: false, server: null, port: null },
    pac_enabled: false,
    wpad_enabled: false,
  }],
  recommended_clash_proxy_services: [],
  proxied_services: ["Wi-Fi"],
  unavailable: ["default_route_interface", "hardware_port", "bsd_device", "recommended_clash_proxy_services"],
};

const responses = {
  boot_payload: {
    product: {
      name: "Clash for Mac",
      version: "0.4.0",
      license: "GPL-3.0-or-later",
      minimum_macos: "15.0",
      architecture: "arm64",
    },
    migration_handoff: false,
    migration_handoff_status: { state: "idle" },
    migration_handoff_renderer_ready: null,
  },
  legacy_retirement_status: { state: "cleared" },
  read_settings_snapshot: {
    persisted: true,
    settings: {
      theme: "system",
      font_family: "",
      retain_window_bounds: true,
      launch_at_login: false,
      silent_start: false,
      check_for_updates: true,
    },
    launch_at_login: {
      persisted_intent: false,
      live_status: "not_registered",
      matches_persisted_intent: true,
    },
  },
  current_platform_design: {
    target: "macos-arm64",
    system_proxy_strategy: "signed ProxyAgent under Global Authority",
    helper_strategy: "no privileged helper; the 0.3.x root helper is retired",
    launchd_strategy: "SMAppService Login Item only",
    tun_strategy: "NetworkExtension Packet Tunnel System Extension",
    intel_supported: false,
    minimum_macos: "15.0",
  },
  engine_snapshot: RUNNING_ENGINE,
  geoip_database_status: {
    present: false,
    file_name: "geoip.metadb",
    path: "/tmp/geoip.metadb",
    mtime_ms: null,
    size_bytes: null,
  },
  controller_version: { version: "1.13.0", meta: true },
  read_runtime_config_text: PROJECTION,
  network_diagnostics: DIAGNOSTICS,
  profiles_snapshot: [{
    id: PROFILE_ID,
    name: "Work",
    active: true,
    bytes: 2048,
    updated_epoch_secs: Math.floor(Date.now() / 1000) - 300,
  }],
  controller_snapshot: {
    config: { "mixed-port": 7890, "allow-lan": false, mode: "rule", "log-level": "info", ipv6: true },
    proxies: {
      groups: [{ name: "Proxy", kind: "Selector", now: "HK", options: ["HK", "JP"], history: [] }],
      proxies: [
        { name: "HK", kind: "Trojan", udp: true, history: [{ time: "t", delay: 42 }] },
        { name: "JP", kind: "Vmess", udp: false, history: [] },
      ],
    },
    connections: {
      upload: 2048,
      download: 4096,
      connections: [{
        id: "c1",
        upload: 10,
        download: 20,
        start: "2026-01-01T00:00:00Z",
        chains: ["HK", "Proxy"],
        rule: "Match",
        rulePayload: "",
        metadata: {
          network: "tcp",
          type: "HTTP",
          sourceIP: "127.0.0.1",
          destinationIP: "1.1.1.1",
          sourcePort: "1",
          destinationPort: "443",
          host: "example.test",
          dnsMode: "normal",
          processPath: "/usr/bin/curl",
        },
      }],
    },
  },
  rules_snapshot: {
    rules: [{ index: null, type: "DOMAIN", payload: "example.test", proxy: "Proxy", size: null, hits: null, provider: null, extra: {} }],
  },
  start_connections_stream: () => startStreamFixture("connections"),
  start_log_stream: () => startStreamFixture("request-logs"),
  stop_connections_stream: stopStreamFixture,
  stop_log_stream: stopStreamFixture,
  refresh_tray_menu: null,
  open_page: null,
  begin_migration_handoff: null,
  check_for_updates: { available: false, current: "0.4.0" },
};
const BASE_CONTROLLER_SNAPSHOT = structuredClone(responses.controller_snapshot);

function controllerSnapshotWith({ mode = "rule", selected = "HK", extraOptions = [] } = {}) {
  const snapshot = structuredClone(BASE_CONTROLLER_SNAPSHOT);
  snapshot.config.mode = mode;
  const group = snapshot.proxies.groups.find((item) => item.name === "Proxy");
  group.now = selected;
  for (const name of [selected, ...extraOptions]) {
    if (!group.options.includes(name)) group.options.push(name);
    if (!snapshot.proxies.proxies.some((item) => item.name === name)) {
      snapshot.proxies.proxies.push({ name, kind: "Vmess", udp: true, history: [] });
    }
  }
  return snapshot;
}

const invoked = [];
const invocationDetails = [];
const rejected = {
  providers_snapshot: "controller capability `provider management` is unsupported by pinned engine sing-box 1.13.15",
};
globalThis.window.__TAURI_INTERNALS__ = {
  transformCallback(callback) {
    const id = nextCallbackId;
    nextCallbackId += 1;
    callbacks.set(id, callback);
    return id;
  },
  async invoke(command, args) {
    if (command === "plugin:event|listen") {
      listeners.set(args.event, callbacks.get(args.handler));
      return nextCallbackId;
    }
    if (command === "plugin:event|unlisten") return null;
    if (command === "check_for_updates") {
      updateListenerWasReady = listeners.has("cfw://update-available");
    }
    invoked.push(command);
    invocationDetails.push({ command, args });
    if (command in rejected) throw new Error(rejected[command]);
    if (!(command in responses)) throw new Error(`no canned response for ${command}`);
    const response = responses[command];
    return typeof response === "function" ? response(args) : response;
  },
};

const appModule = await import("../src/app.js");
const { PAGES, state, runtime } = await import("../src/state.js");
await new Promise((resolve) => setTimeout(resolve, 150));

const emit = async (event, payload) => {
  const result = listeners.get(event)?.({ event, payload });
  if (result && typeof result.then === "function") await result;
  await new Promise((resolve) => setTimeout(resolve, 20));
};
const renderPage = async (id) => {
  page.innerHTML = "";
  await emit("cfw://page", id);
  return page.innerHTML;
};
const setEngine = async (envelope) => {
  responses.engine_snapshot = envelope;
  await emit("cfw://settings-changed", responses.read_settings_snapshot);
};

const dispatchDocumentEvent = async (type, event = {}) => {
  for (const listener of documentListeners.get(type) ?? []) {
    const result = listener({
      target: {},
      preventDefault() {},
      stopPropagation() {},
      ...event,
    });
    if (result && typeof result.then === "function") await result;
  }
  await new Promise((resolve) => setTimeout(resolve, 20));
};

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function waitForInvocation(command, previousCount = 0) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const count = invocationDetails.filter((entry) => entry.command === command).length;
    if (count > previousCount) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail(`${command} was not invoked`);
}

function interactiveElement(tag = "button") {
  const node = element(tag);
  const handlers = new Map();
  node.addEventListener = (type, listener) => handlers.set(type, listener);
  node.trigger = async (type, event = {}) => handlers.get(type)?.({
    currentTarget: node,
    target: node,
    preventDefault() {},
    stopPropagation() {},
    ...event,
  });
  return node;
}

test("bootstrap reaches the dashboard instead of the fatal handler", () => {
  assert.equal(documentStub.body.innerHTML.includes("fatal"), false);
  assert.ok(listeners.has("cfw://page"), "the page event is subscribed during bootstrap");
  assert.ok(invoked.includes("boot_payload"));
  assert.ok(invoked.includes("engine_snapshot"));
  assert.equal(
    invoked.includes("acknowledge_migration_handoff_renderer_ready"),
    false,
    "the ordinary dashboard never acknowledges handoff renderer readiness",
  );
  assert.equal(updateListenerWasReady, true, "automatic update check must start after its listener");
});

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
    responses.profiles_snapshot = [];
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
    assert.match(general, /No profile selected/u);
    assert.doesNotMatch(general, /127\.0\.0\.1:7890/u);
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

test("a failed legacy commit discards the consumed preview and stale retry button", async () => {
  const preview = {
    status: "ready",
    preview_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    name: "Migrated profile",
    source_host: "subscription.example",
    legacy_bytes: 494575,
    active: true,
  };
  const confirm = interactiveElement();
  confirm.dataset.previewId = preview.preview_id;
  rejected.commit_legacy_cfw_profile_migration = "credential vault access was denied";
  state.legacyProfileMigrationPreview = preview;
  state.glassDialog = { kind: "legacy-profile-migration", payload: preview, busy: false, error: null };
  querySelectorAllElements.set("[data-glass-legacy-migration-confirm]", [confirm]);

  try {
    await renderPage("profiles");
    await confirm.trigger("click");
    assert.equal(state.legacyProfileMigrationPreview, null);
    assert.equal(state.glassDialog?.kind, "info");
    assert.match(state.glassDialog?.payload?.body ?? "", /preview the legacy profile again/u);
  } finally {
    delete rejected.commit_legacy_cfw_profile_migration;
    querySelectorAllElements.clear();
    state.glassDialog = null;
    state.legacyProfileMigrationPreview = null;
  }
});

test("legacy migration describes a local cached snapshot and makes no download claim", async () => {
  const originalDialog = state.glassDialog;
  state.glassDialog = {
    kind: "legacy-profile-migration",
    payload: {
      status: "ready",
      preview_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      name: "Cached subscription",
      source_host: "subscription.example",
      legacy_bytes: 4096,
      active: true,
    },
    busy: false,
    error: null,
  };

  try {
    glassRoot.innerHTML = "";
    await renderPage("profiles");
    assert.match(glassRoot.innerHTML, /legacy YAML snapshot saved on this Mac/u);
    assert.match(glassRoot.innerHTML, /Migration does not download a newer subscription/u);
    assert.match(glassRoot.innerHTML, /retained only as the HTTPS update source/u);
    assert.match(glassRoot.innerHTML, /cached YAML is never executed/u);
    assert.doesNotMatch(glassRoot.innerHTML, /using the current HTTPS subscription/u);
  } finally {
    state.glassDialog = originalDialog;
    glassRoot.innerHTML = "";
  }
});

test("runtime configuration preview is offline and depends only on repository-backed selection", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalProfiles = structuredClone(state.profiles);
  const originalProfilesUnavailableReason = state.profilesUnavailableReason;
  const originalDialog = state.glassDialog;

  try {
    state.profiles = [{
      id: PROFILE_ID,
      name: "Work",
      active: true,
      bytes: 2048,
      updatedEpochSecs: null,
      updated: "now",
      traffic: "2 KB",
    }];
    state.profilesUnavailableReason = null;
    await setEngine(OFF_ENGINE);
    state.glassDialog = null;
    invoked.length = 0;
    invocationDetails.length = 0;

    await appModule.handleAction("preview-runtime-config");

    assert.equal(invoked.filter((command) => command === "read_runtime_config_text").length, 1);
    assert.equal(state.glassDialog?.kind, "preview-config");
    assert.equal(state.glassDialog?.payload, PROJECTION);

    state.glassDialog = null;
    state.profilesUnavailableReason = "profile repository unavailable";
    await appModule.handleAction("preview-runtime-config");
    assert.equal(invoked.filter((command) => command === "read_runtime_config_text").length, 1);
    assert.equal(state.glassDialog, null);

    state.profilesUnavailableReason = null;
    state.profiles = [];
    await appModule.handleAction("preview-runtime-config");
    assert.equal(invoked.filter((command) => command === "read_runtime_config_text").length, 1);
    assert.equal(state.glassDialog, null);
  } finally {
    state.profiles = originalProfiles;
    state.profilesUnavailableReason = originalProfilesUnavailableReason;
    state.glassDialog = originalDialog;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

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
      desiredMode: "system_proxy",
    },
    {
      key: "tunMode",
      command: "set_tun_enabled",
      shortcut: "t",
      retry: "retry-tun-mode",
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
      assert.match(requestedInput[1], /checked/u);
      assert.doesNotMatch(requestedInput[1], /disabled/u);

      invoked.length = 0;
      invocationDetails.length = 0;
      input.checked = false;
      await input.trigger("change");
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

test("a fresh zero-group snapshot still exposes the active Direct mode", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  try {
    const direct = controllerSnapshotWith({ mode: "direct" });
    direct.proxies = { groups: [], proxies: [] };
    responses.controller_snapshot = direct;
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();

    const html = await renderPage("proxies");
    const button = html.match(/<button class="selected" data-mode="Direct"([^>]*)>/u);
    assert.ok(button, "Direct must remain visible for a valid profile with zero proxy groups");
    assert.doesNotMatch(button[1], /disabled/u);
    assert.match(html, /Active profile has no proxy groups/u);
  } finally {
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("controller loss clears Direct state until the same engine publishes a fresh snapshot", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const directMode = interactiveElement();
  directMode.dataset.mode = "Direct";
  try {
    const direct = controllerSnapshotWith({ mode: "direct" });
    responses.controller_snapshot = direct;
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();

    responses.controller_snapshot = null;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    assert.equal(state.controllerStatus, "controller offline");
    assert.equal(state.mode, null);
    assert.deepEqual(state.proxyGroups, []);

    querySelectorAllElements.set("[data-mode]", [directMode]);
    const offlineHtml = await renderPage("proxies");
    assert.match(offlineHtml, /data-mode="Direct"[^>]*disabled/u);
    const mutationsBefore = invocationDetails.filter(
      (entry) => entry.command === "set_proxy_mode",
    ).length;
    await directMode.trigger("click");
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "set_proxy_mode").length,
      mutationsBefore,
    );

    responses.controller_snapshot = direct;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    assert.equal(state.controllerStatus, "controller live");
    assert.equal(state.mode, "Direct");
    const recoveredHtml = await renderPage("proxies");
    const recovered = recoveredHtml.match(/<button class="selected" data-mode="Direct"([^>]*)>/u);
    assert.ok(recovered, "Direct must return only after a fresh controller readback");
    assert.doesNotMatch(recovered[1], /disabled/u);
  } finally {
    querySelectorAllElements.clear();
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("Direct fallback state is rendered read-only and cannot select a proxy", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const selection = interactiveElement();
  selection.dataset.group = "GLOBAL";
  selection.dataset.node = "direct";
  try {
    const direct = controllerSnapshotWith({ mode: "direct" });
    direct.proxies = {
      groups: [{ name: "GLOBAL", kind: "Fallback", now: "direct", options: [], history: [] }],
      proxies: [{ name: "direct", kind: "Direct", udp: true, history: [] }],
    };
    responses.controller_snapshot = direct;
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    querySelectorAllElements.set("[data-group][data-node]", [selection]);

    const html = await renderPage("proxies");
    assert.match(html, /data-proxy-node="direct"[^>]*disabled/u);
    assert.match(html, /• direct/u);
    const before = invocationDetails.filter((entry) => entry.command === "select_proxy").length;
    await selection.trigger("click");
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "select_proxy").length,
      before,
      "a read-only Direct observation must never become select_proxy IPC",
    );
  } finally {
    querySelectorAllElements.clear();
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("proxy mode mutations are single-flight and an old failure cannot roll back the latest success", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const originalMutation = responses.set_proxy_mode;
  const hadMutation = Object.hasOwn(responses, "set_proxy_mode");
  const originalBreakOnChange = state.toggles.breakOnProxyChange;
  const first = deferred();
  const second = deferred();
  const actions = [];
  let mutationCall = 0;

  try {
    responses.controller_snapshot = controllerSnapshotWith({ mode: "rule" });
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    state.toggles.breakOnProxyChange = false;

    const globalMode = interactiveElement();
    globalMode.dataset.mode = "Global";
    const directMode = interactiveElement();
    directMode.dataset.mode = "Direct";
    querySelectorAllElements.set("[data-mode]", [globalMode, directMode]);
    await renderPage("proxies");

    responses.set_proxy_mode = () => {
      const result = [first.promise, second.promise][mutationCall];
      mutationCall += 1;
      assert.ok(result, "only the two requested mode mutations may reach native IPC");
      return result;
    };
    responses.controller_snapshot = controllerSnapshotWith({ mode: "direct" });
    const mutationCalls = invocationDetails.filter((entry) => entry.command === "set_proxy_mode").length;
    const snapshotCalls = invocationDetails.filter((entry) => entry.command === "controller_snapshot").length;

    actions.push(globalMode.trigger("click"));
    await waitForInvocation("set_proxy_mode", mutationCalls);
    actions.push(directMode.trigger("click"));
    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.equal(
      invocationDetails.filter((entry) => entry.command === "set_proxy_mode").length,
      mutationCalls + 1,
      "the second mode intent must wait for the first native mutation",
    );
    assert.equal(state.mode, "Direct", "the latest intent is rendered while its native write is queued");

    first.reject(new Error("old-mode-failure-marker"));
    await waitForInvocation("set_proxy_mode", mutationCalls + 1);
    second.resolve(null);
    await Promise.all(actions);

    const calls = invocationDetails
      .filter((entry) => entry.command === "set_proxy_mode")
      .slice(mutationCalls);
    assert.deepEqual(calls.map((entry) => entry.args.mode), ["Global", "Direct"]);
    assert.equal(state.mode, "Direct");
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "controller_snapshot").length,
      snapshotCalls + 1,
      "only the latest mode intent publishes one authoritative controller readback",
    );
    assert.equal(state.logs.some((entry) => entry.message.includes("old-mode-failure-marker")), false);
    assert.ok(state.logs.some((entry) => entry.message === "Proxy mode switched to Direct"));
  } finally {
    first.resolve(null);
    second.resolve(null);
    await Promise.allSettled(actions);
    querySelectorAllElements.clear();
    state.toggles.breakOnProxyChange = originalBreakOnChange;
    if (hadMutation) responses.set_proxy_mode = originalMutation;
    else delete responses.set_proxy_mode;
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("mode and selector mutations share one lane without readback rollback", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const originalModeMutation = responses.set_proxy_mode;
  const originalSelectorMutation = responses.select_proxy;
  const hadModeMutation = Object.hasOwn(responses, "set_proxy_mode");
  const hadSelectorMutation = Object.hasOwn(responses, "select_proxy");
  const originalBreakOnChange = state.toggles.breakOnProxyChange;
  const originalLogs = [...state.logs];
  const modePending = deferred();
  const selectorPending = deferred();
  const actions = [];
  let readbackCall = 0;

  try {
    responses.controller_snapshot = controllerSnapshotWith({ mode: "rule", selected: "HK" });
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    state.toggles.breakOnProxyChange = false;

    const globalMode = interactiveElement();
    globalMode.dataset.mode = "Global";
    const jp = interactiveElement();
    jp.dataset.group = "Proxy";
    jp.dataset.node = "JP";
    querySelectorAllElements.set("[data-mode]", [globalMode]);
    querySelectorAllElements.set("[data-group][data-node]", [jp]);
    await renderPage("proxies");

    responses.set_proxy_mode = modePending.promise;
    responses.select_proxy = selectorPending.promise;
    const modeReadback = controllerSnapshotWith({ mode: "global", selected: "HK" });
    const selectorReadback = controllerSnapshotWith({ mode: "global", selected: "JP" });
    responses.controller_snapshot = () => {
      const snapshot = [modeReadback, selectorReadback][readbackCall];
      readbackCall += 1;
      assert.ok(snapshot, "the mixed mutation lane performs exactly two readbacks");
      return structuredClone(snapshot);
    };
    const modeCalls = invocationDetails.filter(({ command }) => command === "set_proxy_mode").length;
    const selectorCalls = invocationDetails.filter(({ command }) => command === "select_proxy").length;

    actions.push(globalMode.trigger("click"));
    await waitForInvocation("set_proxy_mode", modeCalls);
    actions.push(jp.trigger("click"));
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(state.mode, "Global");
    assert.equal(state.proxyGroups.find(({ name }) => name === "Proxy")?.now, "JP");
    assert.equal(
      invocationDetails.filter(({ command }) => command === "select_proxy").length,
      selectorCalls,
      "selector IPC must wait while the earlier mode mutation is pending",
    );

    modePending.resolve(null);
    await waitForInvocation("select_proxy", selectorCalls);
    assert.equal(state.mode, "Global");
    assert.equal(
      state.proxyGroups.find(({ name }) => name === "Proxy")?.now,
      "JP",
      "mode readback must reapply the queued selector intent",
    );

    selectorPending.resolve(null);
    await Promise.all(actions);
    assert.equal(readbackCall, 2);
    assert.equal(state.mode, "Global");
    assert.equal(state.proxyGroups.find(({ name }) => name === "Proxy")?.now, "JP");
  } finally {
    modePending.resolve(null);
    selectorPending.resolve(null);
    await Promise.allSettled(actions);
    querySelectorAllElements.clear();
    state.toggles.breakOnProxyChange = originalBreakOnChange;
    if (hadModeMutation) responses.set_proxy_mode = originalModeMutation;
    else delete responses.set_proxy_mode;
    if (hadSelectorMutation) responses.select_proxy = originalSelectorMutation;
    else delete responses.select_proxy;
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
    state.logs = originalLogs;
  }
});

test("a controller mutation response from an older engine generation performs zero UI writeback", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const originalMutation = responses.set_proxy_mode;
  const hadMutation = Object.hasOwn(responses, "set_proxy_mode");
  const originalBreakOnChange = state.toggles.breakOnProxyChange;
  const pending = deferred();
  let action = null;
  const nextEngine = {
    ...RUNNING_ENGINE,
    snapshot: {
      ...RUNNING_ENGINE.snapshot,
      generation: 4,
      config_digest: "digest-4",
      state: {
        state: "proxy_active",
        runtime: {
          ...RUNNING_ENGINE.snapshot.state.runtime,
          context: {
            ...RUNNING_ENGINE.snapshot.state.runtime.context,
            generation: 4,
          },
          config_digest: "digest-4",
        },
      },
    },
  };

  try {
    responses.controller_snapshot = controllerSnapshotWith({ mode: "rule" });
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    state.toggles.breakOnProxyChange = false;

    const globalMode = interactiveElement();
    globalMode.dataset.mode = "Global";
    querySelectorAllElements.set("[data-mode]", [globalMode]);
    await renderPage("proxies");
    responses.set_proxy_mode = pending.promise;
    const mutationCalls = invocationDetails.filter((entry) => entry.command === "set_proxy_mode").length;
    const snapshotCalls = invocationDetails.filter((entry) => entry.command === "controller_snapshot").length;

    action = globalMode.trigger("click");
    await waitForInvocation("set_proxy_mode", mutationCalls);
    assert.equal(state.mode, "Global");

    await setEngine(nextEngine);
    assert.equal(state.mode, null, "a new engine identity immediately discards the old optimistic mode");
    pending.resolve(null);
    await action;

    assert.equal(state.mode, null);
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "controller_snapshot").length,
      snapshotCalls,
      "the stale mutation response must not schedule controller readback on the new generation",
    );
    assert.equal(state.logs.some((entry) => entry.message === "Proxy mode switched to Global"), false);
  } finally {
    pending.resolve(null);
    if (action) await action.catch(() => {});
    querySelectorAllElements.clear();
    state.toggles.breakOnProxyChange = originalBreakOnChange;
    if (hadMutation) responses.set_proxy_mode = originalMutation;
    else delete responses.set_proxy_mode;
    responses.controller_snapshot = originalController;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("same-runtime stop and restart rotates provenance and rejects every old envelope", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalConnectionPaused = state.connectionPaused;
  const originalLogsPaused = state.logsPaused;
  const originalLogs = [...state.logs];

  try {
    state.connectionPaused = false;
    state.logsPaused = false;
    responses.engine_snapshot = RUNNING_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    const oldConnections = structuredClone(runtime.connectionsLiveStream.binding);
    const oldLogs = structuredClone(runtime.logLiveStream.binding);
    assert.ok(oldConnections);
    assert.ok(oldLogs);

    await appModule.handleAction("toggle-connection-stream");
    await appModule.handleAction("toggle-log-stream");
    assert.equal(state.connectionPaused, true);
    assert.equal(state.logsPaused, true);
    assert.equal(runtime.connectionsLiveStream.binding, null);
    assert.equal(runtime.logLiveStream.binding, null);

    await appModule.handleAction("toggle-connection-stream");
    await appModule.handleAction("toggle-log-stream");
    const newConnections = structuredClone(runtime.connectionsLiveStream.binding);
    const newLogs = structuredClone(runtime.logLiveStream.binding);
    assert.ok(newConnections.stream_id > oldConnections.stream_id);
    assert.ok(newLogs.stream_id > oldLogs.stream_id);
    assert.deepEqual(newConnections.runtime, oldConnections.runtime);
    assert.deepEqual(newLogs.runtime, oldLogs.runtime);

    state.connections = [];
    await emit("cfw://connections-snapshot", {
      provenance: oldConnections,
      payload: {
        upload: 1,
        download: 1,
        connections: [{
          id: "old-same-runtime-connection",
          upload: 1,
          download: 1,
          start: "2026-01-01T00:00:00Z",
          chains: ["OLD"],
          rule: "MATCH",
          metadata: { host: "old.example" },
        }],
      },
    });
    await emit("cfw://log-lines", {
      provenance: oldLogs,
      payload: [{
        time: "12:00:00",
        level: "info",
        source: "old-stream",
        message: "old same-runtime log",
        fields: [],
      }],
    });
    await emit("cfw://stream-error", {
      provenance: oldConnections,
      payload: {
        stream: "connections",
        message: "old same-runtime stream error",
        level: "warning",
      },
    });
    assert.equal(state.connections.some(({ id }) => id === "old-same-runtime-connection"), false);
    assert.equal(state.logs.some(({ message }) => message === "old same-runtime log"), false);
    assert.equal(state.logs.some(({ message }) => message === "old same-runtime stream error"), false);

    await emit("cfw://connections-snapshot", {
      provenance: newConnections,
      payload: {
        upload: 2,
        download: 2,
        connections: [{
          id: "new-same-runtime-connection",
          upload: 2,
          download: 2,
          start: "2026-01-01T00:00:01Z",
          chains: ["NEW"],
          rule: "MATCH",
          metadata: { host: "new.example" },
        }],
      },
    });
    await emit("cfw://log-lines", {
      provenance: newLogs,
      payload: [{
        time: "12:00:01",
        level: "info",
        source: "new-stream",
        message: "new same-runtime log",
        fields: [],
      }],
    });
    assert.deepEqual(state.connections.map(({ id }) => id), ["new-same-runtime-connection"]);
    assert.equal(state.logs.some(({ message }) => message === "new same-runtime log"), true);
  } finally {
    state.connectionPaused = originalConnectionPaused;
    state.logsPaused = originalLogsPaused;
    state.logs = originalLogs;
    responses.engine_snapshot = originalEngine;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
  }
});

test("a start response superseded by pause cannot republish a running binding", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalStart = responses.start_connections_stream;
  const originalConnectionPaused = state.connectionPaused;
  const originalLogs = [...state.logs];
  const delayedStart = deferred();
  let resumeAction = null;
  let pauseAction = null;

  try {
    state.connectionPaused = false;
    responses.engine_snapshot = RUNNING_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    await appModule.handleAction("toggle-connection-stream");
    assert.equal(state.connectionPaused, true);
    assert.equal(runtime.connectionsLiveStream.binding, null);

    const delayedBinding = startStreamFixture("connections", RUNNING_ENGINE);
    responses.start_connections_stream = delayedStart.promise;
    const startCalls = invocationDetails.filter(({ command }) => (
      command === "start_connections_stream"
    )).length;

    resumeAction = appModule.handleAction("toggle-connection-stream");
    await waitForInvocation("start_connections_stream", startCalls);
    assert.equal(state.connectionPaused, false);
    pauseAction = appModule.handleAction("toggle-connection-stream");
    assert.equal(state.connectionPaused, true, "pause supersedes the in-flight start immediately");

    delayedStart.resolve(delayedBinding);
    await Promise.all([resumeAction, pauseAction]);
    assert.equal(runtime.connectionsLiveStream.binding, null);
    assert.equal(activeStreamBindings.has("connections"), false);

    state.connections = [];
    await emit("cfw://connections-snapshot", {
      provenance: delayedBinding,
      payload: {
        upload: 1,
        download: 1,
        connections: [{
          id: "superseded-start-connection",
          upload: 1,
          download: 1,
          start: "2026-01-01T00:00:00Z",
          chains: ["STALE"],
          rule: "MATCH",
          metadata: { host: "stale-start.example" },
        }],
      },
    });
    assert.deepEqual(state.connections, []);

    responses.start_connections_stream = originalStart;
    await appModule.handleAction("toggle-connection-stream");
    const resumedBinding = runtime.connectionsLiveStream.binding;
    assert.ok(resumedBinding.stream_id > delayedBinding.stream_id);
    assert.equal(state.connectionPaused, false);
  } finally {
    delayedStart.resolve(startStreamFixture("connections", RUNNING_ENGINE));
    if (resumeAction) await resumeAction.catch(() => {});
    if (pauseAction) await pauseAction.catch(() => {});
    responses.start_connections_stream = originalStart;
    state.connectionPaused = originalConnectionPaused;
    state.logs = originalLogs;
    responses.engine_snapshot = originalEngine;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
  }
});

test("runtime A buffered stream events cannot be accepted after runtime B is bound", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalConnectionPaused = state.connectionPaused;
  const originalLogsPaused = state.logsPaused;
  const runtimeB = {
    ...RUNNING_ENGINE,
    snapshot: {
      ...RUNNING_ENGINE.snapshot,
      generation: 4,
      config_digest: "digest-b",
      state: {
        state: "proxy_active",
        runtime: {
          ...RUNNING_ENGINE.snapshot.state.runtime,
          context: {
            ...RUNNING_ENGINE.snapshot.state.runtime.context,
            config_epoch: 2,
            generation: 4,
          },
          config_digest: "digest-b",
        },
      },
    },
  };
  const delayedConnection = {
    upload: 1,
    download: 2,
    connections: [{
      id: "runtime-a-delayed",
      upload: 1,
      download: 2,
      start: "2026-01-01T00:00:00Z",
      chains: ["A"],
      rule: "MATCH",
      metadata: { host: "a-delayed.example" },
    }],
  };
  const liveConnection = {
    upload: 3,
    download: 4,
    connections: [{
      id: "runtime-b-live",
      upload: 3,
      download: 4,
      start: "2026-01-01T00:00:01Z",
      chains: ["B"],
      rule: "MATCH",
      metadata: { host: "b-live.example" },
    }],
  };

  try {
    state.connectionPaused = false;
    state.logsPaused = false;
    responses.engine_snapshot = RUNNING_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    const bindingA = streamBindingFor("connections", RUNNING_ENGINE);

    responses.engine_snapshot = runtimeB;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    const bindingB = streamBindingFor("connections", runtimeB);
    assert.notDeepEqual(bindingA, bindingB);
    state.connections = [];

    await emit("cfw://connections-snapshot", {
      provenance: bindingA,
      payload: delayedConnection,
    });
    await emit("cfw://log-lines", streamEvent("request-logs", [{
      time: "12:00:00",
      level: "info",
      source: "runtime-a",
      message: "runtime A delayed log",
      fields: [],
    }], RUNNING_ENGINE));
    await emit("cfw://stream-error", streamEvent("connections", {
      stream: "connections",
      message: "runtime A delayed error",
      level: "warning",
    }, RUNNING_ENGINE));

    assert.equal(state.connections.some(({ id }) => id === "runtime-a-delayed"), false);
    assert.equal(state.logs.some(({ message }) => message === "runtime A delayed log"), false);
    assert.equal(state.logs.some(({ message }) => message === "runtime A delayed error"), false);

    await emit("cfw://connections-snapshot", {
      provenance: bindingB,
      payload: liveConnection,
    });
    await emit("cfw://log-lines", streamEvent("request-logs", [{
      time: "12:00:01",
      level: "info",
      source: "runtime-b",
      message: "runtime B live log",
      fields: [],
    }], runtimeB));

    assert.deepEqual(state.connections.map(({ id }) => id), ["runtime-b-live"]);
    assert.equal(state.logs.some(({ message }) => message === "runtime B live log"), true);
  } finally {
    state.connectionPaused = originalConnectionPaused;
    state.logsPaused = originalLogsPaused;
    responses.engine_snapshot = originalEngine;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
  }
});

test("a delayed runtime A pause stays serialized across same-runtime refresh and runtime B", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalStop = responses.stop_connections_stream;
  const originalConnectionPaused = state.connectionPaused;
  const delayedStop = deferred();
  let pauseAction = null;
  let sameRuntimeRefresh = null;
  let runtimeTransition = null;
  let resumeAction = null;
  const runtimeB = {
    ...RUNNING_ENGINE,
    snapshot: {
      ...RUNNING_ENGINE.snapshot,
      generation: 5,
      config_digest: "digest-pause-b",
      state: {
        state: "proxy_active",
        runtime: {
          ...RUNNING_ENGINE.snapshot.state.runtime,
          context: {
            ...RUNNING_ENGINE.snapshot.state.runtime.context,
            config_epoch: 3,
            generation: 5,
          },
          config_digest: "digest-pause-b",
        },
      },
    },
  };

  try {
    state.connectionPaused = false;
    responses.engine_snapshot = RUNNING_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    const bindingA = streamBindingFor("connections", RUNNING_ENGINE);
    const stopCalls = invocationDetails.filter(({ command }) => (
      command === "stop_connections_stream"
    )).length;
    const startCalls = invocationDetails.filter(({ command }) => (
      command === "start_connections_stream"
    )).length;
    responses.stop_connections_stream = delayedStop.promise;

    pauseAction = appModule.handleAction("toggle-connection-stream");
    await waitForInvocation("stop_connections_stream", stopCalls);
    assert.equal(state.connectionPaused, true, "pause intent must publish before native completion");
    assert.deepEqual(
      invocationDetails.filter(({ command }) => command === "stop_connections_stream").at(-1)?.args,
      { expected: bindingA },
    );

    const engineCalls = invocationDetails.filter(({ command }) => command === "engine_snapshot").length;
    sameRuntimeRefresh = listeners.get("cfw://engine-event")?.({
      event: "cfw://engine-event",
      payload: { type: "snapshot_changed" },
    });
    await waitForInvocation("engine_snapshot", engineCalls);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(
      invocationDetails.filter(({ command }) => command === "start_connections_stream").length,
      startCalls,
      "a same-runtime refresh must respect the already-published pause intent",
    );

    responses.engine_snapshot = runtimeB;
    runtimeTransition = listeners.get("cfw://engine-event")?.({
      event: "cfw://engine-event",
      payload: { type: "snapshot_changed" },
    });
    await waitForInvocation("engine_snapshot", engineCalls + 1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(
      invocationDetails.filter(({ command }) => command === "start_connections_stream").length,
      startCalls,
      "the pause intent must remain in force when runtime B becomes active",
    );

    delayedStop.resolve(null);
    await Promise.all([pauseAction, sameRuntimeRefresh, runtimeTransition]);
    assert.equal(state.connectionPaused, true);

    resumeAction = appModule.handleAction("toggle-connection-stream");
    await resumeAction;
    assert.equal(state.connectionPaused, false);
    assert.equal(
      invocationDetails.filter(({ command }) => command === "start_connections_stream").length,
      startCalls + 1,
      "resuming must start exactly one stream bound to runtime B",
    );

    state.connections = [];
    await emit("cfw://connections-snapshot", {
      provenance: bindingA,
      payload: { upload: 1, download: 1, connections: [] },
    });
    await emit("cfw://connections-snapshot", streamEvent("connections", {
      upload: 2,
      download: 2,
      connections: [{
        id: "runtime-b-after-stale-stop",
        upload: 2,
        download: 2,
        start: "2026-01-01T00:00:02Z",
        chains: ["B"],
        rule: "MATCH",
        metadata: { host: "runtime-b.example" },
      }],
    }, runtimeB));
    assert.deepEqual(state.connections.map(({ id }) => id), ["runtime-b-after-stale-stop"]);
  } finally {
    delayedStop.resolve(null);
    if (pauseAction) await pauseAction.catch(() => {});
    if (sameRuntimeRefresh) await sameRuntimeRefresh.catch(() => {});
    if (runtimeTransition) await runtimeTransition.catch(() => {});
    if (resumeAction) await resumeAction.catch(() => {});
    responses.stop_connections_stream = originalStop;
    state.connectionPaused = originalConnectionPaused;
    responses.engine_snapshot = originalEngine;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
  }
});

test("proxy selector mutations are single-flight and a failed latest intent publishes controller readback", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalController = responses.controller_snapshot;
  const originalMutation = responses.select_proxy;
  const hadMutation = Object.hasOwn(responses, "select_proxy");
  const originalBreakOnChange = state.toggles.breakOnProxyChange;
  const first = deferred();
  const second = deferred();
  const actions = [];
  let mutationCall = 0;

  try {
    responses.controller_snapshot = controllerSnapshotWith({ selected: "HK", extraOptions: ["SG"] });
    await setEngine(RUNNING_ENGINE);
    await reloadButton.click();
    state.toggles.breakOnProxyChange = false;

    const jp = interactiveElement();
    jp.dataset.group = "Proxy";
    jp.dataset.node = "JP";
    const sg = interactiveElement();
    sg.dataset.group = "Proxy";
    sg.dataset.node = "SG";
    querySelectorAllElements.set("[data-group][data-node]", [jp, sg]);
    await renderPage("proxies");

    responses.select_proxy = () => {
      const result = [first.promise, second.promise][mutationCall];
      mutationCall += 1;
      assert.ok(result, "only the two requested selector mutations may reach native IPC");
      return result;
    };
    responses.controller_snapshot = controllerSnapshotWith({ selected: "JP" });
    const mutationCalls = invocationDetails.filter((entry) => entry.command === "select_proxy").length;
    const snapshotCalls = invocationDetails.filter((entry) => entry.command === "controller_snapshot").length;

    actions.push(jp.trigger("click"));
    await waitForInvocation("select_proxy", mutationCalls);
    actions.push(sg.trigger("click"));
    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.equal(
      invocationDetails.filter((entry) => entry.command === "select_proxy").length,
      mutationCalls + 1,
      "the second selector intent must wait for the first native mutation",
    );
    assert.equal(state.proxyGroups.find((group) => group.name === "Proxy")?.now, "SG");

    first.resolve(null);
    await waitForInvocation("select_proxy", mutationCalls + 1);
    second.reject(new Error("latest-selector-failure-marker"));
    await Promise.all(actions);

    const calls = invocationDetails
      .filter((entry) => entry.command === "select_proxy")
      .slice(mutationCalls);
    assert.deepEqual(calls.map((entry) => entry.args.proxy), ["JP", "SG"]);
    assert.equal(
      state.proxyGroups.find((group) => group.name === "Proxy")?.now,
      "JP",
      "a failed latest selector intent must show authoritative controller state",
    );
    assert.equal(
      invocationDetails.filter((entry) => entry.command === "controller_snapshot").length,
      snapshotCalls + 1,
    );
    assert.ok(state.logs.some((entry) => (
      entry.message.includes("latest-selector-failure-marker")
      && entry.message.includes("controller readback reports JP")
    )));
    assert.equal(state.logs.some((entry) => entry.message === "Proxy group Proxy switched to JP"), false);
  } finally {
    first.resolve(null);
    second.resolve(null);
    await Promise.allSettled(actions);
    querySelectorAllElements.clear();
    state.toggles.breakOnProxyChange = originalBreakOnChange;
    if (hadMutation) responses.select_proxy = originalMutation;
    else delete responses.select_proxy;
    responses.controller_snapshot = originalController;
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

test("Engine generation prevents stale provider and rule snapshots from repopulating Off state", async () => {
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

    responses.engine_snapshot = OFF_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    pendingProviders.resolve({
      proxy_providers: [{ name: "STALE-PROVIDER", kind: "Proxy", vehicle_type: "HTTP", proxies: [] }],
      rule_providers: [{ name: "STALE-RULE-PROVIDER", kind: "Rule", vehicle_type: "HTTP", rules: [] }],
    });
    await providerReload;

    assert.deepEqual(state.providers, []);
    assert.deepEqual(state.ruleProviders, []);
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

test("every page renders", async () => {
  for (const { id } of PAGES) {
    const html = await renderPage(id);
    assert.ok(html.length > 200, `page ${id} rendered ${html.length} characters`);
  }
});

test("Start at Login reflects typed live macOS status without rewriting persisted intent", async () => {
  const original = structuredClone(responses.read_settings_snapshot);
  const cases = [
    {
      persistedIntent: false,
      liveStatus: "enabled",
      matches: false,
      checked: true,
      message: "macOS currently enables this Login Item, while the saved preference says Off",
    },
    {
      persistedIntent: true,
      liveStatus: "not_registered",
      matches: false,
      checked: false,
      message: "The saved preference says On, but macOS reports it is not registered",
    },
    {
      persistedIntent: false,
      liveStatus: "requires_approval",
      matches: false,
      checked: true,
      message: "macOS requires approval in System Settings",
    },
    {
      persistedIntent: false,
      liveStatus: "unknown",
      matches: false,
      checked: false,
      message: "Start at Login is unavailable because macOS returned an unknown Login Item state",
    },
  ];

  try {
    for (const scenario of cases) {
      responses.read_settings_snapshot = {
        ...original,
        settings: {
          ...original.settings,
          launch_at_login: scenario.persistedIntent,
        },
        launch_at_login: {
          persisted_intent: scenario.persistedIntent,
          live_status: scenario.liveStatus,
          matches_persisted_intent: scenario.matches,
        },
      };
      await emit("cfw://settings-changed", responses.read_settings_snapshot);
      const settings = await renderPage("settings");
      assert.equal(state.toggles.startAtLogin, scenario.checked);
      assert.ok(settings.includes(scenario.message), scenario.liveStatus);
      if (scenario.liveStatus === "unknown") {
        assert.match(settings, /data-toggle="startAtLogin"[^>]*disabled/u);
      }
    }
  } finally {
    responses.read_settings_snapshot = original;
    await emit("cfw://settings-changed", original);
  }
});

test("invalid settings events recover from native state or disable persistence", async () => {
  const original = structuredClone(responses.read_settings_snapshot);
  const invalid = structuredClone(original);
  invalid.settings.theme = "dark";
  invalid.settings.launch_at_login = "false";
  invalid.unexpected = true;

  try {
    await emit("cfw://settings-changed", invalid);
    assert.deepEqual(state.settingsSnapshot, original);
    assert.equal(state.settingsUnavailableReason, null);
    assert.ok(state.logs.some((entry) => (
      entry.source === "settings"
      && entry.message.includes("recovered from the native store")
    )));

    responses.read_settings_snapshot = invalid;
    await emit("cfw://settings-changed", invalid);
    const settings = await renderPage("settings");

    assert.equal(state.settingsSnapshot.persisted, false);
    assert.deepEqual(state.settingsSnapshot.settings, {
      theme: "system",
      font_family: "",
      retain_window_bounds: true,
      launch_at_login: false,
      silent_start: false,
      check_for_updates: false,
    });
    assert.deepEqual(state.launchAtLogin, {
      persistedIntent: false,
      liveStatus: "unknown",
      matchesPersistedIntent: false,
    });
    assert.equal(state.toggles.startAtLogin, false);
    assert.equal(state.toggles.silentStart, false);
    assert.equal(state.toggles.checkForUpdates, false);
    assert.equal(state.toggles.retainWindowBounds, true);
    assert.equal(documentStub.documentElement.dataset.theme, "light");
    assert.match(settings, /Preferences are unavailable because the native settings snapshot could not be verified/u);
    assert.match(settings, /data-toggle="startAtLogin"[^>]*disabled/u);
    assert.match(settings, /data-toggle="silentStart"[^>]*disabled/u);
    assert.match(settings, /data-theme-setting disabled/u);
    assert.match(settings, /data-action="save-settings" disabled/u);
    assert.ok(state.logs.some((entry) => (
      entry.level === "error"
      && entry.source === "settings"
      && entry.message.includes("Rejected an invalid settings update")
    )));
  } finally {
    responses.read_settings_snapshot = original;
    await emit("cfw://settings-changed", original);
  }
});

test("malformed Login Item state and fatal startup never echo attacker text", async () => {
  const original = structuredClone(responses.read_settings_snapshot);
  const secret = "<img src=x onerror=fatal-secret>";
  const malformed = {
    ...structuredClone(original),
    launch_at_login: {
      persisted_intent: false,
      live_status: secret,
      matches_persisted_intent: false,
    },
  };
  const originalBody = documentStub.body.innerHTML;

  try {
    responses.read_settings_snapshot = malformed;
    await emit("cfw://settings-changed", malformed);
    assert.equal(state.settingsUnavailableReason !== null, true);
    assert.equal(state.logs.some((entry) => entry.message.includes(secret)), false);

    appModule.renderFatalBootstrap(new Error(`token=fatal-secret ${secret}`));
    assert.match(documentStub.body.innerHTML, /startup_state_unverifiable/u);
    assert.equal(documentStub.body.innerHTML.includes("fatal-secret"), false);
    assert.equal(documentStub.body.innerHTML.includes("<img"), false);
    assert.ok(documentStub.body.innerHTML.length < 512);
  } finally {
    documentStub.body.innerHTML = originalBody;
    responses.read_settings_snapshot = original;
    await emit("cfw://settings-changed", original);
  }
});

test("missing rule metadata and unsupported providers render as unavailable", async () => {
  await setEngine(RUNNING_ENGINE);
  const providerCalls = invocationDetails.filter((entry) => entry.command === "providers_snapshot").length;
  await reloadButton.click();
  assert.equal(
    invocationDetails.filter((entry) => entry.command === "providers_snapshot").length,
    providerCalls,
    "a typed false capability must prevent provider probing",
  );
  state.rules = [{
    index: "unavailable",
    type: "Default",
    payload: "final",
    proxy: "route(proxy)",
    hits: "unavailable",
    size: "unavailable",
  }];
  const rules = await renderPage("rules");
  assert.equal((rules.match(/unavailable/gu) ?? []).length >= 2, true);

  const providers = await renderPage("providers");
  assert.ok(providers.includes("Proxy provider management unavailable"));
  assert.ok(providers.includes("Rule provider management unavailable"));
  assert.ok(providers.includes("unavailable in the pinned sing-box 1.13.15 engine"));
});

test("the General page shows the projected inbound and every refused control's reason", async () => {
  await setEngine(RUNNING_ENGINE);
  const html = await renderPage("general");
  assert.match(html, /127\.0\.0\.1:7890/u);
  assert.match(html, /sing-box · 1\.13\.0/u);
  for (const needle of [
    "the projected mixed inbound is bound to loopback",
    "pins the engine log level to info",
    "Mixin is unavailable",
    "No GeoIP database can be downloaded",
  ]) {
    assert.ok(html.includes(needle), `General page is missing the reason: ${needle}`);
  }
  // Every projection-bound switch must be disabled, not merely unchecked.
  assert.equal((html.match(/disabled/gu) ?? []).length >= 4, true);
});

test("live stream events do not crash the renderer", async () => {
  await setEngine(RUNNING_ENGINE);
  state.logsPaused = true;
  state.connectionPaused = true;
  await appModule.handleAction("toggle-log-stream");
  await appModule.handleAction("toggle-connection-stream");
  await renderPage("logs");
  await emit("cfw://log-lines", streamEvent("request-logs", [
    { time: "12:00:00", level: "info", source: "engine", message: "hello", fields: [{ key: "k", value: "v" }] },
  ]));
  await emit(
    "cfw://connections-snapshot",
    streamEvent("connections", responses.controller_snapshot.connections),
  );
  await emit("cfw://stream-error", streamEvent("connections", {
    stream: "connections",
    message: "socket closed",
    level: "warning",
  }));
  await emit("cfw://engine-event", { type: "boundary_failure", code: "x", message: "boom" });
  await emit("cfw://update-available", { available: true, version: "0.4.1", current: "0.4.0" });
  assert.equal(state.logs.some((entry) => entry.message === "hello"), true);
  assert.equal(state.logs.some((entry) => entry.message.includes("boom")), true);
});

test("every glass dialog renders", async () => {
  const cases = [
    ["copy", { kind: "copy", id: PROFILE_ID }, "Copy profile"],
    ["settings", { kind: "settings", id: PROFILE_ID }, "Edit profile information"],
    ["delete", { kind: "delete", id: PROFILE_ID }, "Delete profile"],
    ["reset-settings", { kind: "reset-settings" }, "Reset all settings"],
    ["preview-config", { kind: "preview-config", payload: PROJECTION }, "Projected configuration"],
    ["network-services", { kind: "network-services", payload: DIAGNOSTICS.services, unavailable: DIAGNOSTICS.unavailable }, "Network services"],
    ["dns-query", { kind: "dns-query", payload: { name: "a.test", type: "A", result: "" } }, "Resolve through the running engine"],
    ["info", { kind: "info", payload: { title: "System DNS", body: "never written" } }, "System DNS"],
    ["product-about", { kind: "product-about", payload: { phase: "idle", update: { available: true, version: "0.4.1" } } }, "Open Download"],
    ["credentials", { kind: "credentials", id: PROFILE_ID }, "Reading credential requirements"],
    ["credential-cleanup", { kind: "credential-cleanup" }, "Unused credentials"],
  ];
  for (const [name, dialog, needle] of cases) {
    state.glassDialog = dialog;
    state.credentialSetup = null;
    state.credentialGcPreview = name === "credential-cleanup"
      ? { previewId: "8f14e45f-ceea-4670-a91e-2f0f1d5e6a7b", orphanCount: 1, orphanReferences: [{ id: PROFILE_ID, kind: "trojan_password" }] }
      : null;
    glassRoot.innerHTML = "";
    await renderPage("general");
    assert.ok(glassRoot.innerHTML.includes(needle), `dialog ${name} did not render "${needle}"`);
  }
  state.glassDialog = null;
  state.credentialGcPreview = null;
});

test("the credential dialog asks for missing values only while the engine is Off", async () => {
  const setup = {
    profileId: PROFILE_ID,
    profileName: "Work",
    requiredCount: 2,
    presentCount: 1,
    missing: [{ id: PROFILE_ID, kind: "trojan_password" }],
    vaultAvailable: true,
    error: null,
  };

  await setEngine(RUNNING_ENGINE);
  state.glassDialog = { kind: "credentials", id: PROFILE_ID };
  state.credentialSetup = setup;
  glassRoot.innerHTML = "";
  await renderPage("general");
  assert.equal(glassRoot.innerHTML.includes("Store credentials"), false);
  assert.ok(glassRoot.innerHTML.includes("require the engine to be Off"));

  await setEngine(OFF_ENGINE);
  state.glassDialog = { kind: "credentials", id: PROFILE_ID };
  state.credentialSetup = setup;
  glassRoot.innerHTML = "";
  await renderPage("general");
  for (const needle of ["Store credentials", "Trojan Password", "1 of 2"]) {
    assert.ok(glassRoot.innerHTML.includes(needle), `credential dialog is missing "${needle}"`);
  }

  state.credentialSetup = {
    profileId: PROFILE_ID,
    profileName: "Work",
    requiredCount: null,
    presentCount: null,
    missing: [],
    vaultAvailable: false,
    error: "vault unavailable",
  };
  glassRoot.innerHTML = "";
  await renderPage("general");
  assert.ok(
    glassRoot.innerHTML.includes("nothing is assumed missing"),
    "the credential dialog must fail closed when the vault cannot answer",
  );
  state.glassDialog = null;
  state.credentialSetup = null;
});

test("profile mutations are offered only while the engine is Off", async () => {
  await setEngine(OFF_ENGINE);
  const off = await renderPage("profiles");
  assert.equal(off.includes("require the engine to be Off"), false);

  await setEngine(RUNNING_ENGINE);
  const running = await renderPage("profiles");
  assert.ok(running.includes("require the engine to be Off"));
});

test("the General page surfaces approval and capability reasons", async () => {
  await setEngine({
    snapshot: { desired_mode: "tunnel", generation: 1, config_digest: null, state: { state: "awaiting_approval", generation: 1 } },
    capabilities: { system_proxy: true, tunnel: true },
  });
  const awaitingApproval = await renderPage("general");
  assert.ok(awaitingApproval.includes("Needs approval"));
  assert.match(awaitingApproval, /data-action="retry-tun-mode">Approve/u);
  assert.match(awaitingApproval, /data-toggle="tunMode" checked/u);

  state.engineMutationBusy = true;
  const mutationBusy = await renderPage("general");
  assert.match(mutationBusy, /data-action="retry-tun-mode" disabled>Approve/u);
  assert.match(mutationBusy, /data-toggle="tunMode" checked disabled/u);
  state.engineMutationBusy = false;

  await setEngine({
    snapshot: {
      desired_mode: "system_proxy",
      generation: 2,
      config_digest: "digest",
      state: { state: "failed", generation: 2, target: "system_proxy", error: "approval required" },
    },
    capabilities: { system_proxy: true, tunnel: true },
  });
  const failedProxy = await renderPage("general");
  assert.match(failedProxy, /data-action="retry-system-proxy">Retry/u);
  assert.match(failedProxy, /data-toggle="systemProxy" checked/u);

  await setEngine({
    snapshot: { desired_mode: "off", generation: 0, config_digest: null, state: { state: "off" } },
    capabilities: { system_proxy: false, tunnel: false },
    unavailable_reason: "native runtime unavailable",
  });
  assert.ok((await renderPage("general")).includes("native runtime unavailable"));
});

test("General routes recovery, post-cutover cleanup and unreadable state without changing pages", async () => {
  state.migrationHandoff = true;
  state.retirement = { state: "recovery_start_required", target: "tunnel", message: "durable journal remains" };
  let html = await renderPage("general");
  assert.ok(html.includes("Recover Replacement"));
  assert.equal(html.includes("Prepare cutover"), false);

  state.retirement = { state: "post_cutover_cleanup_required", message: "old data remains" };
  html = await renderPage("general");
  assert.ok(html.includes("Recover Replacement"));

  state.retirement = { state: "unverifiable", message: "journal unreadable" };
  html = await renderPage("general");
  assert.ok(html.includes("Migration state cannot be verified"));
  assert.equal(html.includes("Prepare cutover"), false);

  state.retirement = { state: "awaiting_confirmation" };
  state.cutover = {
    ...state.cutover,
    target: "system_proxy",
    receiptId: null,
  };
  html = await renderPage("general");
  assert.ok(html.includes("data-cutover-target"));
  assert.ok(html.includes("System Proxy"));
  assert.ok(html.includes("TUN"));

  state.migrationHandoff = false;
  state.retirement = { state: "cleared" };
});

test("migration setup routes an unconfigured install to Profiles before starting the handoff", async () => {
  const originalProfiles = state.profiles;
  const originalRetirement = state.retirement;
  const originalHandoff = state.migrationHandoff;

  try {
    state.profiles = [];
    state.retirement = { state: "awaiting_confirmation" };
    state.migrationHandoff = false;
    const html = await renderPage("general");
    assert.match(html, /cfw-content-migration/u);
    assert.match(html, /Import and select a replacement profile/u);
    assert.match(html, /data-action="open-migration-profiles"/u);
    assert.doesNotMatch(html, /data-action="begin-migration-handoff"/u);

    await appModule.handleAction("open-migration-profiles");
    assert.equal(state.activePage, "profiles");
    assert.deepEqual(invocationDetails.at(-1), {
      command: "open_page",
      args: { page: "profiles" },
    });
  } finally {
    state.profiles = originalProfiles;
    state.retirement = originalRetirement;
    state.migrationHandoff = originalHandoff;
  }
});

test("renderer refresh recovers app-owned handoff progress and terminal failure", async () => {
  state.migrationHandoff = false;
  state.retirement = { state: "awaiting_confirmation" };
  responses.boot_payload.migration_handoff_status = { state: "in_progress" };
  await emit("cfw://engine-event", {
    type: "boundary_failure",
    code: "migration_handoff_failed",
    message: "refresh",
  });
  let html = await renderPage("general");
  assert.equal(state.migrationHandoffStatus.state, "in_progress");
  assert.match(html, /Migration session is starting/u);
  assert.match(html, /data-action="begin-migration-handoff" disabled>Starting…/u);

  responses.boot_payload.migration_handoff_status = {
    state: "failed",
    code: "migration_handoff_failed",
    message: "The migration session did not complete. No legacy cutover was authorized; review the migration log and retry.",
  };
  await emit("cfw://engine-event", {
    type: "boundary_failure",
    code: "migration_handoff_failed",
    message: "refresh",
  });
  html = await renderPage("general");
  assert.equal(state.migrationHandoffStatus.state, "failed");
  assert.match(html, /No legacy cutover was authorized/u);
  assert.match(html, /Retry Migration…/u);
  assert.doesNotMatch(html, /begin-migration-handoff" disabled/u);

  rejected.begin_migration_handoff = "injected readiness failure";
  await appModule.handleAction("begin-migration-handoff");
  assert.equal(state.migrationHandoffStatus.state, "failed");
  assert.equal(invocationDetails.at(-2).command, "begin_migration_handoff");
  assert.equal(invocationDetails.at(-1).command, "boot_payload");
  delete rejected.begin_migration_handoff;

  responses.boot_payload.migration_handoff_status = { state: "idle" };
  state.migrationHandoffStatus = { state: "idle" };
  state.retirement = { state: "cleared" };
});

test("migration actions invoke exact target, receipt and confirmation arguments", async () => {
  state.migrationHandoff = true;
  state.retirement = { state: "awaiting_confirmation" };
  state.cutover = {
    ...state.cutover,
    target: "tunnel",
    receiptId: null,
  };
  responses.prepare_legacy_cutover = { status: "awaiting_approval", target: "tunnel" };
  await appModule.handleAction("prepare-cutover");
  assert.deepEqual(invocationDetails.at(-1), {
    command: "prepare_legacy_cutover",
    args: { target: "tunnel" },
  });
  assert.equal(state.cutover.awaitingApproval, true);
  assert.equal(state.cutover.receiptId, null);

  responses.prepare_legacy_cutover = {
    status: "ready",
    receipt_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    target: "tunnel",
    profile_id: PROFILE_ID,
    valid_for_millis: 60_000,
  };
  await appModule.handleAction("prepare-cutover");
  state.cutover.confirmedReceiptId = state.cutover.receiptId;
  state.cutover.dnsReviewedReceiptId = state.cutover.receiptId;
  responses.disable_service_mode = null;
  responses.legacy_retirement_status = { state: "cleared" };
  await appModule.handleAction("confirm-cutover");
  const disable = invocationDetails.findLast((entry) => entry.command === "disable_service_mode");
  assert.deepEqual(disable, {
    command: "disable_service_mode",
    args: {
      receiptId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      cutoverConfirmed: true,
      dnsReviewConfirmed: true,
    },
  });

  state.migrationHandoff = false;
  state.retirement = { state: "cleared" };
});

test("the Settings page reports the diagnostics fields the backend calls unavailable", async () => {
  const html = await renderPage("settings");
  assert.ok(html.includes("default_route_interface"));
  assert.ok(html.includes("hardware_port"));
  assert.ok(html.includes("Wi-Fi"));
  assert.ok(html.includes("NetworkExtension Packet Tunnel System Extension"));
});
