// The Settings page: Start at Login, Windows startup and setting descriptions,
// fonts, invalid settings events, diagnostics, background controls, and the
// language.
import assert from "node:assert/strict";
import test from "node:test";
import { getLocale } from "../src/i18n.js";
import {
  RUNNING_ENGINE, WINDOWS_PLATFORM_DESIGN, appModule, documentListeners, documentStub, element,
  emit, glassRoot, interactiveElement, invocationDetails, invoked, page, querySelectorAllElements,
  querySelectorElements, rejected, renderPage, responses, setEngine, state,
} from "./support/render-harness.mjs";

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

test("Windows startup shows actual registration and preserves saved intent without claiming launch approval", async () => {
  const original = structuredClone(responses.read_settings_snapshot);
  const product = state.payload.product;
  const hadOpen = Object.hasOwn(responses, "open_login_items_settings");
  const open = responses.open_login_items_settings;
  try {
    state.payload.product = { ...product, name: "Clash for Windows", operating_system: "windows" };
    for (const [intent, status, matches, checked, message] of [
      [true, "registered", true, true, "registration does not confirm launch"],
      [false, "registered", false, true, "saved preference says Off"],
      [true, "not_registered", false, false, "startup registration is absent"],
      [false, "not_registered", true, false, "saved preference is Off"],
      [false, "checking", false, false, "Checking Windows startup registration"],
    ]) {
      const snapshot = {
        ...original,
        settings: { ...original.settings, launch_at_login: intent },
        launch_at_login: { persisted_intent: intent, live_status: status, matches_persisted_intent: matches },
      };
      responses.read_settings_snapshot = snapshot;
      await emit("cfw://settings-changed", snapshot);
      const html = await renderPage("settings");
      assert.equal(state.toggles.startAtLogin, checked);
      assert.equal(state.settingsSnapshot.settings.launch_at_login, intent);
      assert.ok(html.includes(message), status);
      assert.doesNotMatch(html, /Checking macOS Login Item|Enabled by macOS|Disabled by macOS/u);
      assert.match(html, /data-action="open-windows-startup-settings"/u);
    }
    responses.open_login_items_settings = null;
    const before = invoked.length;
    await appModule.handleAction("open-windows-startup-settings");
    assert.deepEqual(invoked.slice(before), ["open_login_items_settings"]);
    state.payload.product = product;
    await assert.rejects(() => appModule.handleAction("open-windows-startup-settings"), /do not apply to this platform/u);
    assert.equal(invoked.length, before + 1, "Windows action has no macOS dispatch");
  } finally {
    state.payload.product = product;
    responses.read_settings_snapshot = original;
    if (hadOpen) responses.open_login_items_settings = open;
    else delete responses.open_login_items_settings;
    await emit("cfw://settings-changed", original);
  }
});

test("Windows settings use native platform descriptions and reject a macOS design payload", async () => {
  const product = state.payload.product;
  const platform = state.platform;
  try {
    state.payload.product = { ...product, name: "Clash for Windows", operating_system: "windows", architecture: "x64" };
    state.platform = WINDOWS_PLATFORM_DESIGN;
    const html = await renderPage("settings");
    for (const text of ["Windows protected storage", "File Explorer", "system tray", "Not available in this development build"]) {
      assert.ok(html.includes(text), text);
    }
    assert.doesNotMatch(html, /Minimum macOS|ARM64-only|Keychain vault|in Finder|Dock icon|launchd|NetworkExtension|System Settings › Network|legacy restore|Avenir Next|SF Mono/u);
    assert.match(html, /Segoe UI/u);
    assert.match(html, /Consolas/u);
    assert.match(html, /Manage DNS for each active adapter in Windows Settings/u);
    state.platform = platform;
    const foreign = await renderPage("settings");
    assert.ok(foreign.includes("The platform design could not be read."));
    assert.doesNotMatch(foreign, /Minimum macOS|15\.0|NetworkExtension|launchd/u);
    state.platform = { target: "windows-x64", tun_strategy: "" };
    const incomplete = await renderPage("settings");
    assert.ok(incomplete.includes("The platform design could not be read."));
  } finally {
    state.payload.product = product;
    state.platform = platform;
  }
});

test("Windows font selection saves its actual family and restores the native value after a refused save", async () => {
  const product = state.payload.product;
  const original = structuredClone(responses.read_settings_snapshot);
  const originalWriter = responses.write_settings_snapshot;
  const originalStyleWriter = document.documentElement.style.setProperty;
  const styles = new Map();
  const handlers = new Map();
  const selector = "[data-theme-setting], [data-font-family], [data-language-setting]";
  const input = element("select");
  input.addEventListener = (type, handler) => handlers.set(type, handler);
  querySelectorElements.set("[data-font-family]", input);
  querySelectorAllElements.set(selector, [input]);
  document.documentElement.style.setProperty = (name, value) => styles.set(name, value);
  responses.write_settings_snapshot = ({ settings }) => {
    const snapshot = { ...original, settings: structuredClone(settings) };
    responses.read_settings_snapshot = snapshot;
    return snapshot;
  };
  try {
    state.payload.product = { ...product, name: "Clash for Windows", operating_system: "windows", architecture: "x64" };
    await emit("cfw://settings-changed", original);
    assert.equal(styles.get("--sans"), '"Segoe UI", system-ui, sans-serif');
    for (const family of ["Segoe UI", "Consolas"]) {
      input.value = family;
      await renderPage("settings");
      const before = invocationDetails.length;
      await handlers.get("change")();
      const writes = invocationDetails.slice(before).filter(({ command }) => command === "write_settings_snapshot");
      assert.equal(writes.length, 1);
      assert.equal(writes[0].args.settings.font_family, family);
      assert.equal(state.settingsSnapshot.settings.font_family, family);
      assert.ok(styles.get("--sans").startsWith(`"${family}", `));
    }
    rejected.write_settings_snapshot = "disk busy";
    input.value = "Segoe UI";
    await handlers.get("change")();
    assert.equal(state.settingsSnapshot.settings.font_family, "Consolas");
    assert.match(page.innerHTML, /value="Consolas" selected/u);
    assert.ok(state.logs.some(({ message }) => message.includes("disk busy")));
    delete rejected.write_settings_snapshot;
    // A recognized saved family remains visible even if it was selected on a
    // different host; changing another preference must not silently erase it.
    const foreign = { ...original, settings: { ...original.settings, font_family: "SF Mono" } };
    await emit("cfw://settings-changed", foreign);
    assert.match(await renderPage("settings"), /value="SF Mono" selected/u);
  } finally {
    delete rejected.write_settings_snapshot;
    state.payload.product = product;
    if (originalWriter === undefined) delete responses.write_settings_snapshot;
    else responses.write_settings_snapshot = originalWriter;
    querySelectorElements.delete("[data-font-family]");
    querySelectorAllElements.delete(selector);
    responses.read_settings_snapshot = original;
    await emit("cfw://settings-changed", original);
    document.documentElement.style.setProperty = originalStyleWriter;
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
      font_family: "", language: "system",
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

test("the Settings page reports the diagnostics fields the backend calls unavailable", async () => {
  const html = await renderPage("settings");
  assert.ok(html.includes("default_route_interface"));
  assert.ok(html.includes("hardware_port"));
  assert.ok(html.includes("Wi-Fi"));
  assert.ok(html.includes("NetworkExtension Packet Tunnel System Extension"));
});

test("background controls render through the dashboard and Escape dismisses the dialog", async () => {
  responses.read_automation_settings = {
    settings: { shortcuts: [], network_enabled: false, network_rules: [] },
    revision: "automation-v1", network: { kind: "wifi", interface: "en0", ssid: null },
  };
  try {
    await renderPage("settings");
    await appModule.handleAction("open-automation-settings");
    assert.match(glassRoot.innerHTML, /aria-labelledby="automation-title"/u);
    assert.match(glassRoot.innerHTML, /data-shortcut-action="show_dashboard"/u);
    assert.match(glassRoot.innerHTML, /data-network-add/u);
    let prevented = false;
    for (const handler of documentListeners.get("keydown") ?? []) {
      handler({ key: "Escape", preventDefault() { prevented = true; } });
    }
    assert.equal(prevented, true);
    assert.equal(state.automationDialog, null);
    assert.doesNotMatch(glassRoot.innerHTML, /automation-title/u);
  } finally {
    state.automationDialog = null;
    delete responses.read_automation_settings;
    await renderPage("settings");
  }
});

test("language selection saves only UI preferences and a refused save restores the verified language", async () => {
  const original = structuredClone(responses.read_settings_snapshot);
  const originalWriter = responses.write_settings_snapshot;
  const handlers = new Map();
  const selector = "[data-theme-setting], [data-font-family], [data-language-setting]";
  const input = element("select");
  input.value = "ja";
  input.addEventListener = (type, handler) => handlers.set(type, handler);
  querySelectorElements.set("[data-language-setting]", input);
  querySelectorAllElements.set(selector, [input]);
  responses.write_settings_snapshot = ({ settings }) => {
    const snapshot = { ...original, settings: structuredClone(settings), resolved_locale: settings.language };
    responses.read_settings_snapshot = snapshot;
    return snapshot;
  };
  try {
    await renderPage("settings");
    const before = invocationDetails.length;
    await handlers.get("change")();
    assert.equal(getLocale(), "ja");
    assert.equal(state.settingsSnapshot.settings.language, "ja");
    const writes = invocationDetails.slice(before).filter(({ command }) => command.startsWith("write_") || command.startsWith("set_") || command === "apply_active_profile");
    assert.deepEqual(writes.map(({ command }) => command), ["write_settings_snapshot"]);
    assert.deepEqual(writes[0].args.settings, { ...original.settings, language: "ja" });
    rejected.write_settings_snapshot = "disk busy";
    input.value = "zh-Hant";
    await handlers.get("change")();
    assert.equal(getLocale(), "ja");
    assert.equal(state.settingsSnapshot.settings.language, "ja");
    assert.ok(state.logs.some(({ message }) => message.includes("disk busy")));
    assert.match(page.innerHTML, /value="ja" selected/u);
  } finally {
    delete rejected.write_settings_snapshot;
    if (originalWriter === undefined) delete responses.write_settings_snapshot;
    else responses.write_settings_snapshot = originalWriter;
    querySelectorElements.delete("[data-language-setting]");
    querySelectorAllElements.delete(selector);
    responses.read_settings_snapshot = original;
    await emit("cfw://settings-changed", original);
  }
});

const RUNTIME_SWITCHES = [
  { key: "mainland_china_direct", toggle: "mainlandChinaDirect", label: "Mainland China direct",
    reason: "traffic that no profile rule matches goes direct when it is bound for mainland China" },
  { key: "dns_leak_protection", toggle: "dnsLeakProtection", label: "DNS leak protection",
    reason: "every connection to port 853 is refused" },
];

for (const sw of RUNTIME_SWITCHES) {
  test(`Settings places the ${sw.label} switch after Allow LAN and applies it as one runtime transaction`, async () => {
    await setEngine(RUNNING_ENGINE);
    const original = structuredClone(responses.read_runtime_settings_snapshot);
    const hadWrite = Object.hasOwn(responses, "write_runtime_settings_snapshot");
    const previousWrite = responses.write_runtime_settings_snapshot;
    const toggle = (html) => html.match(new RegExp(`<input type="checkbox" data-toggle="${sw.toggle}"([^>]*)\\/>`, "u"))?.[1];
    try {
      let html = await renderPage("settings");
      const order = ["allowLan", "mainlandChinaDirect", "dnsLeakProtection", "mixin"].map((key) => html.indexOf(`data-toggle="${key}"`));
      assert.ok(order.every((position, index) => position >= 0 && (index === 0 || order[index - 1] < position)), `row order ${order}`);
      assert.ok(html.includes(`<b>${sw.label}</b>`));
      assert.ok(html.includes(sw.reason));
      assert.doesNotMatch(toggle(html), /checked|disabled/u);

      let written = null;
      responses.write_runtime_settings_snapshot = (args) => {
        written = args;
        responses.read_runtime_settings_snapshot = { settings: args.settings, revision: "on",
          effective: { ...original.effective, [sw.key]: args.settings[sw.key] } };
        return structuredClone(responses.read_runtime_settings_snapshot);
      };
      const input = interactiveElement("input");
      input.dataset.toggle = sw.toggle;
      querySelectorAllElements.set("[data-toggle]", [input]);
      await renderPage("settings");
      invocationDetails.length = 0;
      input.checked = true;
      await input.trigger("change");
      const commands = invocationDetails.map((entry) => entry.command);
      assert.deepEqual(commands.filter((command) => command.startsWith("write_")), ["write_runtime_settings_snapshot"]);
      assert.ok(commands.indexOf("read_runtime_settings_snapshot") < commands.indexOf("write_runtime_settings_snapshot"),
        "the write is bound to a fresh read");
      assert.deepEqual(written, { settings: { ...original.settings, [sw.key]: true }, revision: null });
      assert.equal(state.toggles[sw.toggle], true);
      html = await renderPage("settings");
      assert.match(toggle(html), /checked/u);

      // While the runtime settings are unknown the switch is disabled with the reason.
      state.runtimeSettingsError = "runtime settings unavailable";
      html = await renderPage("settings");
      assert.match(toggle(html), /disabled/u);
      assert.match(toggle(html), /title="runtime settings unavailable"/u);
    } finally {
      state.runtimeSettingsError = null;
      responses.read_runtime_settings_snapshot = original;
      if (hadWrite) responses.write_runtime_settings_snapshot = previousWrite;
      else delete responses.write_runtime_settings_snapshot;
      querySelectorAllElements.delete("[data-toggle]");
      await emit("cfw://settings-changed", responses.read_settings_snapshot);
    }
  });
}
