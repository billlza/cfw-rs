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
let nextCallbackId = 1;

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
const glassRoot = element("div", "glass-menu-root");
const documentStub = {
  documentElement: element("html"),
  body: element("body"),
  title: "",
  hidden: false,
  getElementById: (id) => {
    if (id === "page") return page;
    if (id === "glass-menu-root") return glassRoot;
    return element("div", id);
  },
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: (tag) => element(tag),
  createDocumentFragment: () => ({ childNodes: [], appendChild() {} }),
  addEventListener() {},
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
  capabilities: { system_proxy: true, tunnel: true },
  cutover_ready: true,
  cutover_unavailable_reason: null,
  unavailable_reason: null,
};

const OFF_ENGINE = {
  snapshot: { desired_mode: "off", generation: 0, config_digest: null, state: { state: "off" } },
  capabilities: { system_proxy: true, tunnel: true },
  unavailable_reason: null,
};

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
  },
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
  providers_snapshot: {
    proxy_providers: [{
      name: "P",
      kind: "Http",
      vehicle_type: "HTTP",
      behavior: null,
      updated_at: "now",
      proxies: ["HK"],
      rules: [],
      extra: { healthCheck: { lastResult: "ok" } },
    }],
    rule_providers: [{
      name: "R",
      kind: "Http",
      vehicle_type: "HTTP",
      behavior: "domain",
      updated_at: "now",
      proxies: [],
      rules: ["a"],
      extra: {},
    }],
  },
  rules_snapshot: {
    rules: [{ index: 0, type: "DOMAIN", payload: "example.test", proxy: "Proxy", size: -1, provider: null, extra: { hitCount: 3 } }],
  },
  start_connections_stream: null,
  start_log_stream: null,
  refresh_tray_menu: null,
  open_page: null,
};

const invoked = [];
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
    invoked.push(command);
    if (!(command in responses)) throw new Error(`no canned response for ${command}`);
    return responses[command];
  },
};

await import("../src/app.js");
const { state } = await import("../src/state.js");
await new Promise((resolve) => setTimeout(resolve, 150));

const emit = async (event, payload) => {
  listeners.get(event)?.({ event, payload });
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

test("bootstrap reaches the dashboard instead of the fatal handler", () => {
  assert.equal(documentStub.body.innerHTML.includes("fatal"), false);
  assert.ok(listeners.has("cfw://page"), "the page event is subscribed during bootstrap");
  assert.ok(invoked.includes("boot_payload"));
  assert.ok(invoked.includes("engine_snapshot"));
});

test("every page renders", async () => {
  for (const id of ["general", "proxies", "profiles", "providers", "logs", "connections", "rules", "settings", "feedback"]) {
    const html = await renderPage(id);
    assert.ok(html.length > 200, `page ${id} rendered ${html.length} characters`);
  }
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
  await renderPage("logs");
  await emit("cfw://log-lines", [
    { time: "12:00:00", level: "info", source: "engine", message: "hello", fields: [{ key: "k", value: "v" }] },
  ]);
  await emit("cfw://connections-snapshot", responses.controller_snapshot.connections);
  await emit("cfw://stream-error", { stream: "connections", message: "socket closed", level: "warning" });
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
    ["product-about", { kind: "product-about", payload: { phase: "idle", update: { available: true, version: "0.4.1" } } }, "Download & Install"],
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
  assert.ok((await renderPage("general")).includes("Needs approval"));

  await setEngine({
    snapshot: { desired_mode: "off", generation: 0, config_digest: null, state: { state: "off" } },
    capabilities: { system_proxy: false, tunnel: false },
    unavailable_reason: "native runtime unavailable",
  });
  assert.ok((await renderPage("general")).includes("native runtime unavailable"));
});

test("the Settings page reports the diagnostics fields the backend calls unavailable", async () => {
  const html = await renderPage("settings");
  assert.ok(html.includes("default_route_interface"));
  assert.ok(html.includes("hardware_port"));
  assert.ok(html.includes("Wi-Fi"));
  assert.ok(html.includes("NetworkExtension Packet Tunnel System Extension"));
});
