// Runs the restored dashboard against a minimal DOM and a canned IPC surface.
//
// The dashboard is a single self-bootstrapping module, exactly as in 0.3.5, so
// this module stubs what a WebView provides and drives the real bootstrap. Each
// render test file imports it, so each one starts a fresh dashboard in its own
// process, and then renders the pages, the dialogs, and the engine states that
// change what the General page is allowed to claim. A render-time crash or a
// missing reason therefore fails in CI instead of in the app.
import assert from "node:assert/strict";

const listeners = new Map();
const callbacks = new Map();
const querySelectorElements = new Map();
const querySelectorAllElements = new Map();
const documentListeners = new Map();
const intervalCallbacks = [];
let nextCallbackId = 1;
let updateListenerWasReady = false;
let updateOutcomeQueries = 0;

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
const nav = element("nav", "nav");
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
const statusBarNodes = new Map(["upload-rate", "download-rate", "runtime-value", "traffic-progress"]
  .map((id) => [id, element("div", id)]));
const documentStub = {
  documentElement: element("html"),
  body: element("body"),
  title: "",
  hidden: false,
  getElementById: (id) => {
    if (id === "page") return page;
    if (id === "nav") return nav;
    if (id === "glass-menu-root") return glassRoot;
    if (id === "reload-button") return reloadButton;
    if (statusBarNodes.has(id)) return statusBarNodes.get(id);
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
const windowListeners = new Map();
globalThis.window = {
  document: documentStub,
  innerWidth: 900,
  innerHeight: 700,
  addEventListener: (type, handler) => { windowListeners.set(type, handler); },
  // As in a browser, the callback runs only after requestAnimationFrame has
  // returned its handle. Running it first would leave every frame handle the
  // dashboard stores set forever, and its schedulers dead after one use.
  requestAnimationFrame: (callback) => {
    setImmediate(callback);
    return 1;
  },
  setTimeout: (callback, delay) => setTimeout(callback, delay),
  setInterval: (callback, delay) => {
    intervalCallbacks.push({ callback, delay });
    return intervalCallbacks.length;
  },
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
  capabilities: { system_proxy: true, tunnel: true, tunnel_system_proxy: true, provider_management: false },
  cutover_ready: true,
  cutover_unavailable_reason: null,
  unavailable_reason: null,
};

const OFF_ENGINE = {
  snapshot: { desired_mode: "off", generation: 0, config_digest: null, state: { state: "off" } },
  capabilities: { system_proxy: true, tunnel: true, tunnel_system_proxy: true, provider_management: false },
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

const WINDOWS_PLATFORM_DESIGN = Object.freeze({
  target: "windows-x64",
  system_proxy_strategy: "Current-user Windows proxy with owned restoration",
  helper_strategy: "Windows authority service and ordinary-user Agent",
  startup_strategy: "Current-user sign-in registration; Windows controls startup approval",
  tun_strategy: "Not available in this development build",
});

const responses = {
  boot_payload: {
    native_ui: { profile_menu: false, runtime_settings: false, general_switches: false, prompt_dialog: false, window_glass: false },
    product: {
      name: "Clash for Mac",
      version: "0.4.0",
      license: "GPL-3.0-or-later",
      operating_system: "macos",
      minimum_os_version: "15.0",
      architecture: "arm64",
    },
    migration_handoff: false,
    migration_handoff_status: { state: "idle" },
    migration_handoff_renderer_ready: null,
  },
  legacy_retirement_status: { state: "cleared" },
  read_runtime_settings_snapshot: {
    tunnel_mtu_limits: { minimum: 1280, maximum: 1500 },
    settings: { preferred_mixed_port:null, log_level:"info", tunnel_mtu:1500, allow_lan:false, lan_proxy:null },
    revision: null,
    effective: { mixed_port:7890, log_level:"info", tunnel_mtu:1500, ipv6_dns_enabled:true, lan_proxy:null, mainland_china_direct:false, dns_leak_protection:false },
  },
  read_settings_snapshot: {
      resolved_locale: "en",
    persisted: true,
    settings: {
      theme: "system",
      font_family: "", language: "system",
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
  controller_version: { version: "sing-box 1.13.0", meta: true },
  read_runtime_config_text: PROJECTION,
  network_diagnostics: DIAGNOSTICS,
  profiles_snapshot: {
    profiles: [{
      id: PROFILE_ID,
      name: "Work",
      active: true,
      bytes: 2048,
      updated_epoch_secs: Math.floor(Date.now() / 1000) - 300,
      source_kind: "local",
    }],
    invalid_profiles: [],
  },
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
  resolve_update_install: { outcome: { state: "none" }, pending: null },
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
const initialLiveSettings = responses.read_settings_snapshot;
const slowLoginItemQuery = deferred();
let initialLiveQueryPending = true;
let bootstrapReady = false;
let bootstrapFailed = false;
const bootstrapOutcome = deferred();
globalThis.window.__CFM_STARTUP__ = {
  ready() { bootstrapReady = true; bootstrapOutcome.resolve(); },
  fail() { bootstrapFailed = true; bootstrapOutcome.resolve(); },
};
responses.read_settings_snapshot = (args) => {
  if (args?.includeLoginItemStatus === false) {
    return {
      ...initialLiveSettings,
      launch_at_login: {
        persisted_intent: initialLiveSettings.settings.launch_at_login,
        live_status: "checking",
        matches_persisted_intent: false,
      },
    };
  }
  if (initialLiveQueryPending) {
    initialLiveQueryPending = false;
    return slowLoginItemQuery.promise;
  }
  return initialLiveSettings;
};
const rejected = {
  providers_snapshot: "controller capability `provider management` is unsupported by the pinned sing-box engine",
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
      if (args.event === "cfw://engine-event" && startupRaceCase === "listen-refused") {
        throw new Error("engine listener registration refused");
      }
      listeners.set(args.event, callbacks.get(args.handler));
      if (args.event === "cfw://engine-event" && startupRaceCase === "after-subscribe") {
        await completeInitialNativeReconciliation();
      }
      return nextCallbackId;
    }
    if (command === "plugin:event|unlisten") return null;
    if (command === "check_for_updates") {
      updateListenerWasReady = listeners.has("cfw://update-available");
    }
    if (command === "resolve_update_install") updateOutcomeQueries += 1;
    invoked.push(command);
    invocationDetails.push({ command, args });
    if (command in rejected) throw new Error(rejected[command]);
    if (!(command in responses)) throw new Error(`no canned response for ${command}`);
    const response = responses[command];
    return typeof response === "function" ? response(args) : response;
  },
};

// Execute the real bootstrap under deterministic native/event timing. The
// matrix test runs this harness in fresh Node processes for the other cases.
const startupRaceCase = process.env.CFM_TEST_STARTUP_RACE ?? "running";
assert.ok(["running", "off", "failed", "listen-refused", "after-subscribe", "stale-read"].includes(startupRaceCase));
const initialProfilesSnapshot = responses.profiles_snapshot;
let nativeCompletionBeforeListener = false;
let initialCompletionDelivered = false;
const pendingEngine = {
  ...OFF_ENGINE,
  snapshot: { desired_mode: "off", generation: 1, config_digest: null,
    state: { state: "failed", generation: 1, target: "off",
      error: "native startup reconciliation is pending" } },
};
const failedReconciliation = {
  ...pendingEngine,
  startup_recovery_available: true,
  snapshot: { ...pendingEngine.snapshot,
    state: { ...pendingEngine.snapshot.state, error: "native service status unavailable" } },
};
responses.engine_snapshot = pendingEngine;
async function completeInitialNativeReconciliation() {
  if (initialCompletionDelivered) return;
  initialCompletionDelivered = true;
  responses.profiles_snapshot = initialProfilesSnapshot;
  responses.engine_snapshot = startupRaceCase === "off" ? OFF_ENGINE
    : startupRaceCase === "failed" ? failedReconciliation : RUNNING_ENGINE;
  const listener = listeners.get("cfw://engine-event");
  nativeCompletionBeforeListener = !listener;
  if (startupRaceCase === "stale-read") {
    responses.engine_snapshot = () => {
      const delayed = deferred();
      responses.engine_snapshot = RUNNING_ENGINE;
      queueMicrotask(async () => {
        try {
          await listeners.get("cfw://engine-event")({ event: "cfw://engine-event", payload: { type: "snapshot_changed" } });
          delayed.resolve(OFF_ENGINE);
        } catch (error) { delayed.reject(error); }
      });
      return delayed.promise;
    };
  }
  if (listener) await listener({ event: "cfw://engine-event", payload: { type: "snapshot_changed" } });
}
responses.profiles_snapshot = async () => {
  if (startupRaceCase !== "after-subscribe") await completeInitialNativeReconciliation();
  return initialProfilesSnapshot;
};

// The page loads the dashboard through its entry module.
await import("../../src/main.js");
const appModule = await import("../../src/app.js");
const { PAGES, state, runtime } = await import("../../src/state.js");
// The dashboard's own startup recovery attempts are timed; the tests below
// that exercise them set their own delays, every other test runs without.
runtime.startupRecovery.delays = [];
let bootstrapDeadline;
try {
  await Promise.race([
    bootstrapOutcome.promise,
    new Promise((_, reject) => { bootstrapDeadline = setTimeout(() => reject(new Error("bootstrap did not settle")), 2000); }),
  ]);
} finally { clearTimeout(bootstrapDeadline); }
const startupObservedEngine = structuredClone(state.engine);
const startupInvocationCommands = invoked.slice();
const responsiveBeforeLoginItemReply = bootstrapReady && listeners.has("cfw://page");
const loginItemWasPending = state.launchAtLogin.liveStatus === "checking";
// The remainder of this file exercises app.js's standalone fatal boundary;
// startup.test.mjs separately executes the real independent startup guard.
delete globalThis.window.__CFM_STARTUP__;
slowLoginItemQuery.resolve(initialLiveSettings);
responses.read_settings_snapshot = initialLiveSettings;
await new Promise((resolve) => setTimeout(resolve, 20));
const startupUpdateReport = {
  queries: updateOutcomeQueries,
  errors: state.logs.filter((entry) => entry.source === "updater" && entry.level === "error"),
  dialog: state.glassDialog,
  install: state.updateInstall,
};

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

const OVERLAY_SLOTS = ["glassDialog", "profileContextMenu", "runtimeSettingsDialog", "automationDialog"];

const UPDATE_COMMANDS = [
  "prepare_update_install", "commit_update_install", "cancel_update_install", "open_available_update",
];

export {
  DIAGNOSTICS, OFF_ENGINE, OVERLAY_SLOTS, PAGES, PROFILE_ID, PROJECTION, RUNNING_ENGINE,
  UPDATE_COMMANDS, WINDOWS_PLATFORM_DESIGN, activeStreamBindings, appModule, bootstrapFailed,
  bootstrapReady, controllerSnapshotWith, deferred, dispatchDocumentEvent, documentListeners,
  documentStub, element, emit, glassRoot, initialLiveSettings, interactiveElement,
  intervalCallbacks, invocationDetails, invoked, listeners, loginItemWasPending,
  nativeCompletionBeforeListener, nav, page, querySelectorAllElements, querySelectorElements,
  rejected, reloadButton, renderPage, responses, responsiveBeforeLoginItemReply, runtime,
  setEngine, startStreamFixture, startupInvocationCommands, startupObservedEngine,
  startupRaceCase, startupUpdateReport, state, statusBarNodes, streamBindingFor, streamEvent,
  updateListenerWasReady, waitForInvocation,
};
