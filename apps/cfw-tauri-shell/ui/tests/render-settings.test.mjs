// The Settings page: Start at Login, Windows startup and setting descriptions,
// fonts, invalid settings events, diagnostics, background controls, and the
// language.
import assert from "node:assert/strict";
import test from "node:test";
import { getLocale } from "../src/i18n.js";
import { networkSettingsKnown, networkSettingsReason } from "../src/reasons.js";
import { savedSettingsNotInForce } from "../src/runtime-settings.js";
import {
  RUNNING_ENGINE, WINDOWS_PLATFORM_DESIGN, appModule, documentListeners, documentStub, element,
  emit, glassRoot, interactiveElement, invocationDetails, invoked, page, querySelectorAllElements,
  querySelectorElements, rejected, renderPage, responses, setEngine, state,
} from "./support/render-harness.mjs";
import { readRuntimeSettings, refuseRuntimeSettingsRead } from "./support/runtime-settings-reads.mjs";

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
    for (const text of ["Windows protected storage", "File Explorer", "system tray", "Wintun adapter created and routed by the Windows authority service"]) {
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
  { key: "webrtc_leak_protection", toggle: "webrtcLeakProtection", label: "WebRTC leak protection",
    reason: "STUN is refused, so a web page cannot ask a STUN server" },
  // The one switch that is on until the user turns it off.
  { key: "tcp_concurrency", toggle: "tcpConcurrency", label: "TCP concurrency", resting: true,
    reason: "the core connects to them at once and keeps the first connection that opens" },
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
      const order = ["allowLan", "mainlandChinaDirect", "dnsLeakProtection", "webrtcLeakProtection", "tcpConcurrency", "mixin"].map((key) => html.indexOf(`data-toggle="${key}"`));
      assert.ok(order.every((position, index) => position >= 0 && (index === 0 || order[index - 1] < position)), `row order ${order}`);
      assert.ok(html.includes(`<b>${sw.label}</b>`));
      assert.ok(html.includes(sw.reason));
      const resting = sw.resting === true;
      assert.equal(/checked/u.test(toggle(html)), resting, "the switch shows its resting state");
      assert.doesNotMatch(toggle(html), /disabled/u);

      let written = null;
      responses.write_runtime_settings_snapshot = (args) => {
        written = args;
        responses.read_runtime_settings_snapshot = { ...original, settings: args.settings, revision: "changed",
          effective: { ...original.effective, [sw.key]: args.settings[sw.key] } };
        return structuredClone(responses.read_runtime_settings_snapshot);
      };
      const input = interactiveElement("input");
      input.dataset.toggle = sw.toggle;
      querySelectorAllElements.set("[data-toggle]", [input]);
      await renderPage("settings");
      invocationDetails.length = 0;
      input.checked = !resting;
      await input.trigger("change");
      const commands = invocationDetails.map((entry) => entry.command);
      assert.deepEqual(commands.filter((command) => command.startsWith("write_")), ["write_runtime_settings_snapshot"]);
      assert.ok(commands.indexOf("read_runtime_settings_snapshot") < commands.indexOf("write_runtime_settings_snapshot"),
        "the write is bound to a fresh read");
      assert.deepEqual(written, { settings: { ...original.settings, [sw.key]: !resting }, revision: null, basis: { in_force: true, saved_ipv6_dns_enabled: true } });
      assert.equal(state.toggles[sw.toggle], !resting);
      html = await renderPage("settings");
      assert.equal(/checked/u.test(toggle(html)), !resting, "the switch shows the saved change");

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

// The engine's switches and the port dialog change the runtime network
// settings. What a switch would show is unknown until those settings have
// been read, and in a migration's own window the migration owns the network.
test("the availability of the runtime network settings follows the state it is asked about", () => {
  const migrating = "Finish migration before changing network settings";
  const asked = (changes) => ({
    migrationHandoff: false, migrationHandoffStatus: { state: "idle" }, runtimeSettings: { in_force: true }, runtimeSettingsError: null, ...changes,
  });
  // The state asked about, the reason that holds the controls, and whether a
  // switch may show its value. Nothing is taken from the dashboard's own state.
  for (const [changes, reason, known] of [
    [{}, null, true],
    [{ runtimeSettings: null }, "Network settings are loading", false],
    [{ runtimeSettings: null, runtimeSettingsError: "read failed" }, "read failed", false],
    [{ runtimeSettingsError: "reload failed" }, "reload failed", false],
    [{ migrationHandoff: true }, migrating, true],
    // What leaves the values unknown is said first, in the window of a
    // migration too: a switch is then drawn off whatever the setting is.
    [{ migrationHandoff: true, runtimeSettings: null }, "Network settings are loading", false],
    [{ migrationHandoff: true, runtimeSettingsError: "reload failed" }, "reload failed", false],
    [{ migrationHandoff: true, runtimeSettings: null, runtimeSettingsError: "read failed" }, "read failed", false],
    // Settings that are saved but not the ones the engine runs with are known
    // and held. A migration's window and a failed read are said before that.
    [{ runtimeSettings: { in_force: false } }, savedSettingsNotInForce(), true],
    [{ runtimeSettings: {} }, savedSettingsNotInForce(), true],
    [{ migrationHandoff: true, runtimeSettings: { in_force: false } }, migrating, true],
    [{ runtimeSettings: { in_force: false }, runtimeSettingsError: "reload failed" }, "reload failed", false],
    // The window that starts a migration is left as it was: it closes when
    // the migration's window is ready.
    [{ migrationHandoffStatus: { state: "in_progress" } }, null, true],
    [{ migrationHandoffStatus: { state: "failed", code: "migration_handoff_failed", message: "not completed" } }, null, true],
  ]) {
    assert.equal(networkSettingsReason(asked(changes)), reason, JSON.stringify(changes));
    assert.equal(networkSettingsKnown(asked(changes)), known, JSON.stringify(changes));
  }
});

test("Settings holds every runtime network control until its settings are read and may change", async () => {
  await setEngine(RUNNING_ENGINE);
  const original = responses.read_runtime_settings_snapshot;
  const handoff = state.migrationHandoff;
  const handoffStatus = state.migrationHandoffStatus;
  const switches = ["allowLan", "mainlandChinaDirect", "dnsLeakProtection", "webrtcLeakProtection", "tcpConcurrency"];
  const controls = (html) => new Map([
    ...switches.map((key) => [key, html.match(new RegExp(`<input type="checkbox" data-toggle="${key}"([^>]*)\\/>`, "u"))?.[1]]),
    ["open-runtime-settings", html.match(/<button class="button ghost" data-action="open-runtime-settings"([^>]*)>/u)?.[1]],
  ]);
  // The page reads settings that have the listed switches on.
  const read = (on) => readRuntimeSettings(original, {
    allowLan: on.includes("allowLan"),
    mainland_china_direct: on.includes("mainlandChinaDirect"),
    dns_leak_protection: on.includes("dnsLeakProtection"),
    webrtc_leak_protection: on.includes("webrtcLeakProtection"),
    tcp_concurrency: on.includes("tcpConcurrency"),
  });
  // Every control is disabled and says why. A switch shows that it is on only
  // when it is listed: a value that was read is known although it cannot be
  // changed, and one that was not read or may be stale is claimed by no switch.
  const held = async (reason, on = []) => {
    for (const [name, attributes] of controls(await renderPage("settings"))) {
      assert.match(attributes, /disabled/u, `${name} while: ${reason}`);
      assert.ok(attributes.includes(`title="${reason}"`), `${name} says: ${reason}`);
      assert.equal(/checked/u.test(attributes), on.includes(name), `${name} while: ${reason}`);
    }
  };
  const free = async (on) => {
    for (const [name, attributes] of controls(await renderPage("settings"))) {
      assert.doesNotMatch(attributes, /disabled|title=/u, name);
      assert.equal(/checked/u.test(attributes), on.includes(name), name);
    }
  };
  const migrating = "Finish migration before changing network settings";
  const refused = "runtime settings unavailable";
  try {
    // Read: every control is free and every switch shows its value.
    await read(["tcpConcurrency"]);
    await free(["tcpConcurrency"]);
    await read(switches);
    await free(switches);

    // A switch reads the settings for its own action. When the host refuses
    // that read, the click changes nothing and the page holds every control
    // with the refusal, as after any other failed read.
    const input = interactiveElement("input");
    input.dataset.toggle = "dnsLeakProtection";
    querySelectorAllElements.set("[data-toggle]", [input]);
    await renderPage("settings");
    rejected.read_runtime_settings_snapshot = refused;
    invocationDetails.length = 0;
    input.checked = false;
    await input.trigger("change");
    delete rejected.read_runtime_settings_snapshot;
    querySelectorAllElements.delete("[data-toggle]");
    assert.deepEqual(invocationDetails.map((entry) => entry.command).filter((command) => command.includes("runtime_settings")),
      ["read_runtime_settings_snapshot"]);
    await held(refused);
    // A held switch cannot be clicked again. Reload From Disk asks for the
    // network settings once more: while the host still refuses, the controls
    // stay held and the log says why; once it answers, they are free.
    const failures = () => state.logs.filter((entry) => entry.message === `Network settings failed: ${refused}`).length;
    const failed = failures();
    rejected.read_runtime_settings_snapshot = refused;
    await appModule.handleAction("reload-settings");
    delete rejected.read_runtime_settings_snapshot;
    assert.equal(failures(), failed + 1);
    await held(refused);
    await appModule.handleAction("reload-settings");
    assert.equal(failures(), failed + 1);
    await free(switches);
    await refuseRuntimeSettingsRead(refused);
    await held(refused);
    await read(switches);
    await free(switches);

    // A failed reload keeps the snapshot it had beside the error, and the
    // switches may be stale by then: none shows a value.
    await refuseRuntimeSettingsRead(refused);
    await held(refused);
    // As at startup, before the first read: no snapshot.
    state.runtimeSettings = null;
    state.runtimeSettingsError = null;
    await held("Network settings are loading");
    // A first read that failed says why instead.
    await refuseRuntimeSettingsRead(refused);
    await held(refused);

    // The window of a migration. What leaves the values unknown is still
    // said first. Once they are read the migration holds them, and each
    // switch shows its value.
    state.migrationHandoff = true;
    await held(refused);
    state.runtimeSettingsError = null;
    await held("Network settings are loading");
    await read(switches);
    await held(migrating, switches);
    await refuseRuntimeSettingsRead(refused);
    await held(refused);
    await read(["dnsLeakProtection"]);
    await held(migrating, ["dnsLeakProtection"]);

    // The window that starts a migration keeps its controls until it closes.
    state.migrationHandoff = false;
    state.migrationHandoffStatus = { state: "in_progress" };
    await free(["dnsLeakProtection"]);
  } finally {
    delete rejected.read_runtime_settings_snapshot;
    querySelectorAllElements.delete("[data-toggle]");
    responses.read_runtime_settings_snapshot = original;
    state.migrationHandoff = handoff;
    state.migrationHandoffStatus = handoffStatus;
    state.runtimeSettingsError = null;
    await emit("cfw://settings-changed", responses.read_settings_snapshot);
  }
});

// The fixture of these tests answers as the host does. The host stores a
// switch only while it is away from where it rests, also when the snapshot
// the fixture starts from has the switch stored.
test("the stand-in host no longer stores a switch that is back where it rests", async () => {
  const original = responses.read_runtime_settings_snapshot;
  try {
    await readRuntimeSettings(original, { tcp_concurrency: false, dns_leak_protection: true });
    const away = state.runtimeSettings;
    assert.deepEqual([away.settings.tcp_concurrency, away.settings.dns_leak_protection], [false, true]);
    assert.deepEqual([away.effective.tcp_concurrency, away.effective.dns_leak_protection], [false, true]);
    await readRuntimeSettings(away, { webrtc_leak_protection: true });
    const back = state.runtimeSettings;
    assert.deepEqual(back.settings, { ...original.settings, ipv6_dns_enabled: true, webrtc_leak_protection: true });
    assert.deepEqual(back.effective, { ...original.effective, webrtc_leak_protection: true });
  } finally {
    responses.read_runtime_settings_snapshot = original;
    await emit("cfw://settings-changed", responses.read_settings_snapshot);
  }
});
