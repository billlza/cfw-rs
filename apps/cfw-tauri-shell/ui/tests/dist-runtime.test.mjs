import assert from "node:assert/strict";
import test from "node:test";

function webviewElement(tag = "div", id = "") {
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
    scrollIntoView() {},
    firstElementChild: null,
  };
}

test("the generated dist bundle performs no controller or provider IPC while Engine is Off", async () => {
  const callbacks = new Map();
  const invocations = [];
  let nextCallbackId = 1;
  const page = webviewElement("section", "page");
  const body = webviewElement("body");
  const reload = webviewElement("button", "reload-button");
  const documentStub = {
    documentElement: webviewElement("html"),
    body,
    title: "",
    hidden: false,
    getElementById(id) {
      if (id === "page") return page;
      if (id === "reload-button") return reload;
      return webviewElement("div", id);
    },
    querySelector: () => null,
    querySelectorAll: () => [],
    createElement: (tag) => webviewElement(tag),
    createDocumentFragment: () => ({ childNodes: [], appendChild() {} }),
    addEventListener() {},
  };
  globalThis.document = documentStub;
  globalThis.window = {
    document: documentStub,
    innerWidth: 900,
    innerHeight: 700,
    requestAnimationFrame(callback) {
      callback();
      return 1;
    },
    setTimeout,
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
    read_settings_snapshot: {
      persisted: true,
      settings: {
        theme: "system",
        font_family: "",
        retain_window_bounds: true,
        launch_at_login: false,
        silent_start: false,
        check_for_updates: false,
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
      helper_strategy: "retired",
      launchd_strategy: "SMAppService Login Item only",
      tun_strategy: "NetworkExtension Packet Tunnel System Extension",
      intel_supported: false,
      minimum_macos: "15.0",
    },
    engine_snapshot: {
      snapshot: {
        desired_mode: "off",
        generation: 0,
        config_digest: null,
        state: { state: "off" },
      },
      capabilities: {
        system_proxy: false,
        tunnel: false,
        provider_management: false,
      },
      cutover_ready: false,
      cutover_unavailable_reason: "replacement profile is not staged",
      unavailable_reason: "legacy network remains unchanged",
    },
    geoip_database_status: {
      present: false,
      file_name: "geoip.metadb",
      path: null,
      mtime_ms: null,
      size_bytes: null,
    },
    legacy_retirement_status: { state: "awaiting_confirmation" },
    network_diagnostics: {
      default_route_interface: null,
      service_order: [],
      services: [],
      recommended_clash_proxy_services: [],
      proxied_services: [],
      unavailable: ["default_route_interface"],
    },
    profiles_snapshot: [],
  };
  globalThis.window.__TAURI_INTERNALS__ = {
    transformCallback(callback) {
      const id = nextCallbackId;
      nextCallbackId += 1;
      callbacks.set(id, callback);
      return id;
    },
    async invoke(command) {
      if (command === "plugin:event|listen") return nextCallbackId;
      if (command === "plugin:event|unlisten") return null;
      invocations.push(command);
      if (!Object.hasOwn(responses, command)) {
        throw new Error(`unexpected dist smoke IPC: ${command}`);
      }
      return responses[command];
    },
  };

  await import(`../dist/main.js?dist-smoke=${Date.now()}`);
  await new Promise((resolve) => setTimeout(resolve, 200));

  assert.equal(body.innerHTML.includes("startup_state_unverifiable"), false);
  for (const command of [
    "controller_snapshot",
    "controller_version",
    "providers_snapshot",
    "rules_snapshot",
    "start_connections_stream",
    "start_log_stream",
  ]) {
    assert.equal(invocations.includes(command), false, `${command} must not run from dist while Off`);
  }
});
