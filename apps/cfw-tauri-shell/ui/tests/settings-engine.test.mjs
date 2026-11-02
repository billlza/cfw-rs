import { clipboard, dom, element, host, spy } from "./support/fake-host.mjs";
import { replaceEngineIdentity, runEngine, stopEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state, runtime, defaultSettingsSnapshot } from "../src/state.js";
import { createGeneralActions } from "../src/general-actions.js";
import { createEngineActions } from "../src/engine-actions.js";
import { createToggles } from "../src/toggles.js";
import { createSettingsController } from "../src/settings-controller.js";
import { createEngineStatus } from "../src/engine-status.js";
import { engineToggleCapability, engineToggleChangeAllowed } from "../src/engine-capability.js";
import { loadNetworkDiagnostics, loadPlatformDesign } from "../src/system-info.js";
import { launchAtLoginPresentation, normalizeLaunchAtLoginState, normalizeSettingsSnapshot } from "../src/settings-snapshot.js";

const lastLog = () => state.logs[0];
const messages = () => state.logs.map((entry) => entry.message);

const SETTINGS = Object.freeze({
  check_for_updates: true, font_family: "", language: "system", launch_at_login: false,
  retain_window_bounds: true, silent_start: false, theme: "system",
});
const snapshotOf = (settings = {}, loginItem = {}) => ({
  persisted: true,
  resolved_locale: "en",
  settings: { ...SETTINGS, ...settings },
  launch_at_login: { persisted_intent: false, live_status: "not_registered", matches_persisted_intent: true, ...loginItem },
});

beforeEach(() => {
  host.reset();
  dom.reset();
  clipboard.written.length = 0;
  clipboard.writeError = null;
  state.logs = [];
  state.payload = { product: { name: "Clash for Mac", version: "0.5.1", operating_system: "macos", architecture: "arm64" }, native_ui: {} };
  state.glassDialog = null;
  state.projection = { mixedPort: 7890, error: null };
  state.settingsUnavailableReason = null;
  state.engineMutationBusy = false;
  state.engineMutationError = null;
  state.migrationHandoff = false;
  state.activePage = "general";
  runtime.startupRecovery.delays = [];
  stopEngine();
});

test("General copies terminal proxy commands for the projected port, or says why it cannot", async () => {
  const renderPage = spy();
  const { actions } = createGeneralActions({ renderPage, renderGlassOverlays: spy(), automationSettingsUI: {}, runtimeSettingsUI: {} });
  await actions["copy-proxy-exports"]();
  assert.match(clipboard.written[0], /export https_proxy=http:\/\/127\.0\.0\.1:7890/u);
  assert.equal(lastLog().level, "info");
  clipboard.writeError = new Error("denied");
  await actions["copy-proxy-exports"]();
  assert.equal(lastLog().message, "denied");
  state.projection = { mixedPort: null, error: "the selected profile is invalid" };
  await actions["copy-proxy-exports"]();
  assert.equal(lastLog().message, "The projected inbound port is unavailable: the selected profile is invalid");
  state.projection = { mixedPort: null, error: null };
  await actions["copy-proxy-exports"]();
  assert.equal(lastLog().message, "The projected inbound port is unavailable: no active profile is selected");
  assert.equal(renderPage.count(), 4);
});

test("General explains LAN sharing, TUN, Mixin and system DNS in an info dialog", async () => {
  const renderGlassOverlays = spy();
  const { actions } = createGeneralActions({ renderPage: spy(), renderGlassOverlays, automationSettingsUI: {}, runtimeSettingsUI: {} });
  for (const [action, title] of [["allow-lan-info", "Allow LAN"], ["tun-info", "TUN Mode"], ["mixin-info", "Mixin"], ["tun-restore-dns-info", "System DNS"]]) {
    await actions[action]();
    assert.equal(state.glassDialog.kind, "info");
    assert.equal(state.glassDialog.payload.title, title);
    assert.ok(state.glassDialog.payload.body.length > 20, action);
  }
  assert.equal(renderGlassOverlays.count(), 4);
});

test("General opens folders, Windows startup settings, other pages and the settings dialogs", async () => {
  const automationSettingsUI = { open: spy(async () => undefined) };
  const runtimeSettingsUI = { open: spy(async () => undefined) };
  const renderPage = spy();
  const { actions } = createGeneralActions({ renderPage, renderGlassOverlays: spy(), automationSettingsUI, runtimeSettingsUI });
  host.respond("reveal_home_directory", null);
  await actions["open-home-directory"]();
  assert.equal(lastLog().message, "Home Directory opened in Finder");
  state.payload.product.operating_system = "windows";
  await actions["open-home-directory"]();
  assert.equal(lastLog().message, "Home Directory opened in File Explorer");
  host.respond("reveal_home_directory", new Error("gone"));
  await actions["open-home-directory"]();
  assert.equal(lastLog().message, "Open Folder failed: gone");
  host.respond("open_login_items_settings", null);
  await actions["open-windows-startup-settings"]();
  assert.equal(lastLog().message, "Opened Windows Startup settings");
  host.respond("open_login_items_settings", new Error("no settings app"));
  await actions["open-windows-startup-settings"]();
  assert.equal(lastLog().message, "Windows Startup settings could not be opened: no settings app");
  await actions["open-automation-settings"]();
  await actions["open-runtime-settings"]();
  assert.equal(automationSettingsUI.open.count(), 1);
  assert.equal(runtimeSettingsUI.open.count(), 1);
  await actions["open-providers"]();
  assert.equal(state.activePage, "providers");
  await actions["open-settings"]();
  assert.equal(state.activePage, "settings");
});

test("engine actions retry, cancel and start through the network switches", async () => {
  const applyToggle = spy(async () => true);
  const reconcileStartupServices = spy(async () => "recovered");
  const renderPage = spy();
  const { actions } = createEngineActions({ renderPage, reconcileStartupServices, applyToggle, applyUiToggle: spy() });
  assert.equal(await actions["reconcile-startup-services"](), "recovered");
  await actions["retry-system-proxy"]();
  await actions["toggle-core"]();
  state.engine = { ...state.engine, desiredMode: "system_proxy" };
  await actions["toggle-core"]();
  await actions["cancel-system-proxy"]("cancel-system-proxy");
  await actions["cancel-tun-mode"]("cancel-tun-mode");
  assert.deepEqual(applyToggle.calls, [
    ["systemProxy", true, "explicit retry"],
    ["coreRunning", true, "core"],
    ["coreRunning", false, "core"],
    ["systemProxy", false, "cancel request"],
    ["tunMode", false, "cancel request"],
  ]);
  assert.equal(renderPage.count(), 5, "each action renders once");
});

test("a TUN retry opens Login Items while the extension awaits approval and reports a refusal", async () => {
  host.respond("open_login_items_settings", null);
  let admitted = true;
  const applyToggle = spy(async () => admitted);
  const renderPage = spy();
  const { actions } = createEngineActions({ renderPage, reconcileStartupServices: spy(), applyToggle, applyUiToggle: spy() });
  state.engine = { ...state.engine, state: "AwaitingApproval" };
  await actions["retry-tun-mode"]();
  assert.deepEqual(host.commands(), ["open_login_items_settings"]);
  assert.equal(lastLog().message, "Opened System Settings › General › Login Items & Extensions");
  state.engine = { ...state.engine, state: "Running" };
  await actions["retry-tun-mode"]();
  assert.equal(host.commands().length, 1, "a running tunnel needs no approval");
  admitted = false;
  await actions["retry-tun-mode"]();
  assert.equal(host.commands().length, 1);
  createEngineActions({ renderPage, reconcileStartupServices: spy(), applyToggle: spy(async () => { throw new Error("busy"); }), applyUiToggle: spy() });
  await createEngineActions({ renderPage, reconcileStartupServices: spy(), applyToggle: spy(async () => { throw new Error("busy"); }), applyUiToggle: spy() }).actions["retry-tun-mode"]();
  assert.equal(lastLog().message, "TUN retry failed: busy");
  assert.equal(renderPage.count(), 4);
});

test("flushing the fake-IP cache needs a running engine and reports for that engine only", async () => {
  const renderPage = spy();
  const { actions, bindPage } = createEngineActions({ renderPage, reconcileStartupServices: spy(), applyToggle: spy(), applyUiToggle: spy() });
  await actions["flush-fake-ip-cache"]();
  assert.equal(lastLog().message, "Fake IP cache flush is unavailable while the engine is Off");
  runEngine();
  host.respond("flush_fake_ip_cache", null);
  await actions["flush-fake-ip-cache"]();
  assert.equal(lastLog().message, "Fake IP cache flushed through the engine controller");
  host.respond("flush_fake_ip_cache", new Error("controller down"));
  await actions["flush-fake-ip-cache"]();
  assert.equal(state.controllerStatus, "controller offline");
  assert.equal(lastLog().message, "Fake IP cache flush failed: controller down");
  const renders = renderPage.count();
  host.respond("flush_fake_ip_cache", () => { replaceEngineIdentity(); return null; });
  await actions["flush-fake-ip-cache"]();
  runEngine();
  host.respond("flush_fake_ip_cache", () => { replaceEngineIdentity(); return new Error("late"); });
  await actions["flush-fake-ip-cache"]();
  assert.equal(renderPage.count(), renders);

  const applyUiToggle = spy(async () => undefined);
  const toggle = element("input", { dataset: { toggle: "tunMode" }, checked: true });
  dom.setAll("[data-toggle]", [toggle]);
  createEngineActions({ renderPage, reconcileStartupServices: spy(), applyToggle: spy(), applyUiToggle }).bindPage();
  await toggle.fire("change");
  assert.deepEqual(applyUiToggle.calls, [["tunMode", true]]);
  void bindPage;
});

function toggleDeps(overrides = {}) {
  return {
    renderPage: spy(),
    runtimeSettingsUI: {
      toggleLAN: spy(async () => "lan"), toggleIPv6DNS: spy(async () => "ipv6"),
      toggleMainlandChinaDirect: spy(async () => "cn"), toggleDnsLeakProtection: spy(async () => "dns"),
    },
    applyEngineStatus: spy((status) => { state.engine = { ...state.engine, ...status }; }),
    loadEngineStatus: spy(async () => true),
    loadRuntimeProjection: spy(async () => true),
    applyPersistedSettings: spy(),
    persistedSettingsFromUi: () => ({ ...SETTINGS }),
    loadSettingsSnapshot: spy(async () => snapshotOf()),
    ...overrides,
  };
}

test("runtime settings switches go to the runtime settings transaction", async () => {
  const d = toggleDeps();
  const { applyToggle } = createToggles(d);
  assert.equal(await applyToggle("allowLan", true), "lan");
  assert.equal(await applyToggle("ipv6DNS", false), "ipv6");
  assert.equal(await applyToggle("mainlandChinaDirect", true), "cn");
  assert.equal(await applyToggle("dnsLeakProtection", true), "dns");
  await assert.rejects(() => applyToggle("teleport", true, "ui"), /Unknown setting switch/u);
});

test("a network switch is refused while unavailable or busy, and applies the host's status", async () => {
  const d = toggleDeps();
  const { applyToggle } = createToggles(d);
  assert.equal(await applyToggle("systemProxy", true, "ui"), false);
  assert.match(lastLog().message, /System Proxy cannot be enabled/u);
  state.engine = { ...state.engine, systemProxyAvailable: true, localProxyAvailable: true, tunnelAvailable: true };
  state.engineMutationBusy = true;
  await assert.rejects(() => applyToggle("systemProxy", true, "ui"), /already in progress/u);
  state.engineMutationBusy = false;
  host.respond("set_system_proxy_enabled", { mode: "system_proxy" });
  host.respond("network_diagnostics", { services: [] });
  assert.equal(await applyToggle("systemProxy", true, "ui"), true);
  assert.deepEqual(d.applyEngineStatus.calls, [[{ mode: "system_proxy" }]]);
  assert.equal(state.engineMutationBusy, false);
  assert.match(lastLog().message, /^systemProxy request completed; engine /u);
  host.respond("set_core_enabled", { mode: "local" });
  host.respond("set_tun_enabled", { mode: "tunnel" });
  assert.equal(await applyToggle("coreRunning", true, "ui"), true);
  assert.equal(await applyToggle("tunMode", false, "ui"), true);
  assert.equal(d.loadRuntimeProjection.count(), 3);
});

test("a superseded network status is re-read instead of applied", async () => {
  state.engine = { ...state.engine, systemProxyAvailable: true, localProxyAvailable: true, tunnelAvailable: true };
  const d = toggleDeps();
  const { applyToggle } = createToggles(d);
  for (const [key, command] of [["coreRunning", "set_core_enabled"], ["systemProxy", "set_system_proxy_enabled"], ["tunMode", "set_tun_enabled"]]) {
    host.respond(command, () => { runtime.engineStatusRequestId += 1; return {}; });
    host.respond("network_diagnostics", { services: [] });
    assert.equal(await applyToggle(key, true, "ui"), true, key);
  }
  assert.equal(d.applyEngineStatus.count(), 0);
  assert.equal(d.loadEngineStatus.count(), 3);
});

test("a running engine is read back from the controller after a mode change", async () => {
  state.engine = { ...state.engine, systemProxyAvailable: true, localProxyAvailable: true, tunnelAvailable: true };
  const d = toggleDeps({ applyEngineStatus: spy(() => runEngine({ systemProxyAvailable: true, localProxyAvailable: true, tunnelAvailable: true, tunnelSystemProxyAvailable: true })) });
  host.respond("set_core_enabled", {});
  host.respond("set_system_proxy_enabled", {});
  host.respond("set_tun_enabled", {});
  host.respond("network_diagnostics", { services: [] });
  host.respond("controller_snapshot", { config: { mode: "rule" }, proxies: { groups: [] } });
  host.respond("refresh_tray_menu", null);
  const { applyToggle } = createToggles(d);
  await applyToggle("coreRunning", true, "ui");
  await applyToggle("systemProxy", true, "ui");
  await applyToggle("tunMode", true, "ui");
  assert.equal(host.argsOf("controller_snapshot").length, 3);
});

test("a refused network switch restores its state, records the reason and re-reads the engine", async () => {
  state.engine = { ...state.engine, systemProxyAvailable: true, localProxyAvailable: true, tunnelAvailable: true };
  const d = toggleDeps();
  host.respond("set_tun_enabled", new Error("extension refused ".repeat(60)));
  await assert.rejects(() => createToggles(d).applyToggle("tunMode", true, "ui"), /extension refused/u);
  assert.equal(state.engineMutationError.length, 512);
  assert.equal(d.loadEngineStatus.count(), 1);
  assert.equal(state.engineMutationBusy, false);
  const failing = toggleDeps({ loadEngineStatus: spy(async () => { throw new Error("status unreadable"); }) });
  await assert.rejects(() => createToggles(failing).applyToggle("tunMode", true, "ui"));
  assert.equal(lastLog().message, "Could not refresh mode state after refusal: status unreadable");
});

test("preferences switch through the settings store, session switches stay in this window", async () => {
  const d = toggleDeps();
  const { applyToggle, applyUiToggle } = createToggles(d);
  host.respond("write_settings_snapshot", snapshotOf({ silent_start: true }));
  assert.equal(await applyToggle("silentStart", true, "ui"), true);
  assert.equal(state.toggles.silentStart, true);
  assert.deepEqual(host.argsOf("write_settings_snapshot")[0], { settings: { ...SETTINGS } });
  assert.equal(await applyToggle("breakOnProxyChange", true, "ui"), undefined);
  assert.equal(lastLog().message, "breakOnProxyChange changed to on for this session");
  assert.deepEqual(host.argsOf("write_settings_snapshot").length, 1, "a session switch is never written");
  host.respond("set_launch_at_login_enabled", snapshotOf({ launch_at_login: true }));
  assert.equal(await applyToggle("startAtLogin", true, "ui"), true);
  state.settingsUnavailableReason = "settings unverifiable";
  await assert.rejects(() => applyToggle("checkForUpdates", true, "ui"), /settings unverifiable/u);
  state.settingsUnavailableReason = null;
  host.respond("set_launch_at_login_enabled", new Error("approval needed"));
  state.toggles.startAtLogin = false;
  await assert.rejects(() => applyToggle("startAtLogin", true, "ui"), /approval needed/u);
  assert.equal(state.toggles.startAtLogin, false, "a refused switch keeps its previous value");
  assert.equal(d.loadSettingsSnapshot.count(), 1);
  const failing = toggleDeps({ loadSettingsSnapshot: spy(async () => { throw new Error("store unreadable"); }) });
  await assert.rejects(() => createToggles(failing).applyToggle("startAtLogin", true, "ui"));
  assert.equal(lastLog().message, "Could not refresh the Login Item state after refusal: store unreadable");
  await applyUiToggle("teleport", true);
  assert.equal(lastLog().message, "teleport refused: Unknown setting switch");
  assert.equal(d.renderPage.count() >= 1, true);
});

function controller(overrides = {}) {
  const windowGlass = { refresh: spy() };
  const d = { windowGlass, renderPage: spy(), renderGlassOverlays: spy(), loadProfilesSnapshot: spy(async () => true), closeGlassDialog: spy(), ...overrides };
  return { d, settings: createSettingsController(d) };
}

test("an applied settings snapshot sets the switches, the appearance and the language", () => {
  const { d, settings } = controller();
  const html = element("html");
  document.documentElement = html;
  dom.setAll("[data-i18n]", [element("span", { dataset: { i18n: "General" } })]);
  dom.byId("nav", element("nav"));
  dom.byId("reload-button", element("button"));
  settings.applyPersistedSettings(snapshotOf({ theme: "dark", silent_start: true }, { live_status: "requires_approval", persisted_intent: false, matches_persisted_intent: false }));
  assert.equal(document.documentElement.dataset.theme, "dark");
  assert.equal(state.toggles.startAtLogin, true, "a registration awaiting approval is shown on");
  assert.equal(state.toggles.silentStart, true);
  assert.equal(d.windowGlass.refresh.count(), 1);
  assert.equal(document.getElementById("nav").getAttribute("aria-label"), "Primary navigation");
  settings.applyPersistedSettings(snapshotOf({ theme: "light" }));
  assert.equal(document.documentElement.dataset.theme, "light");
  window.matchMedia = () => ({ matches: true });
  settings.applyPersistedSettings(snapshotOf({ theme: "system" }));
  assert.equal(document.documentElement.dataset.theme, "dark", "system follows the OS appearance");
  window.matchMedia = () => ({ matches: false });
  settings.resetPersistedSettingsToSafeState();
  assert.equal(state.settingsSnapshot.persisted, defaultSettingsSnapshot.persisted);
  assert.equal(state.toggles.startAtLogin, false);
  assert.equal(state.launchAtLogin.liveStatus, "unknown");
});

test("the settings form refuses an unknown language or font and falls back to the system theme", () => {
  const { settings } = controller();
  state.settingsSnapshot = snapshotOf();
  dom.set("[data-theme-setting]", element("select", { value: "neon" }));
  assert.equal(settings.persistedSettingsFromUi().theme, "system");
  dom.set("[data-language-setting]", element("select", { value: "klingon" }));
  assert.throws(() => settings.persistedSettingsFromUi(), /Invalid language preference/u);
  dom.set("[data-language-setting]", element("select", { value: "en" }));
  dom.set("[data-font-family]", element("select", { value: "Comic" }));
  assert.throws(() => settings.persistedSettingsFromUi(), /Invalid font preference/u);
});

test("settings are saved, reloaded and reset through their actions", async () => {
  const { d, settings } = controller();
  state.settingsSnapshot = snapshotOf();
  host.respond("write_settings_snapshot", snapshotOf());
  await settings.actions["save-settings"]();
  assert.equal(lastLog().message, "Preferences saved");
  host.respond("read_settings_snapshot", snapshotOf());
  await settings.actions["reload-settings"]();
  assert.equal(lastLog().message, "Preferences reloaded from disk");
  await settings.actions["reset-settings"]();
  assert.deepEqual(state.glassDialog, { kind: "reset-settings" });
  assert.equal(d.renderGlassOverlays.count(), 1);
  state.settingsUnavailableReason = "unverifiable";
  await assert.rejects(() => settings.actions["save-settings"](), /unverifiable/u);
  await assert.rejects(() => settings.actions["reset-settings"](), /unverifiable/u);
});

test("the reset dialog resets preferences once, keeps a refused dialog open and offers its prompt", async () => {
  const { d, settings } = controller();
  const dialog = { kind: "reset-settings" };
  const prompt = settings.dialogs.prompt(dialog);
  assert.equal(prompt.title, "Reset all settings");
  assert.match(settings.dialogs.render(dialog, null, prompt), /data-glass-reset-confirm/u);
  const confirm = element("button");
  dom.setAll("[data-glass-reset-confirm]", [confirm]);
  settings.dialogs.bind();
  state.glassDialog = dialog;
  host.respond("reset_settings_snapshot", snapshotOf());
  const event = await confirm.fire("click");
  assert.equal(event.defaultPrevented, true);
  assert.deepEqual(d.closeGlassDialog.calls, [[dialog]]);
  assert.equal(lastLog().message, "Preferences reset to defaults");
  host.respond("reset_settings_snapshot", new Error("store locked"));
  await prompt.buttons[1].activate();
  assert.equal(lastLog().message, "Reset failed: store locked");
  assert.equal(d.closeGlassDialog.count(), 1);
});

test("appearance changes are saved, and a refusal recovers from the native store or disables persistence", async () => {
  const { d, settings } = controller();
  const theme = element("select", { value: "dark" });
  dom.setAll("[data-theme-setting], [data-font-family], [data-language-setting]", [theme]);
  dom.set("[data-theme-setting]", theme);
  settings.bindPage();
  state.settingsSnapshot = snapshotOf();
  host.respond("write_settings_snapshot", snapshotOf({ theme: "dark" }));
  await theme.fire("change");
  assert.equal(lastLog().message, "Appearance saved");
  host.respond("write_settings_snapshot", new Error("disk full"));
  host.respond("read_settings_snapshot", snapshotOf());
  await theme.fire("change");
  assert.ok(messages().includes("Appearance refused: disk full"));
  assert.equal(state.settingsUnavailableReason, null, "a readable store recovers");
  host.respond("read_settings_snapshot", new Error("store corrupt"));
  await theme.fire("change");
  assert.match(state.settingsUnavailableReason, /Preferences are unavailable/u);
  assert.equal(lastLog().message, "Appearance recovery failed: store corrupt");
  await theme.fire("change");
  assert.equal(lastLog().level, "warning", "unavailable preferences are not written");
  assert.equal(d.renderPage.count(), 4);
});

test("the startup Login Item read applies only to the snapshot it was taken for", async () => {
  const { d, settings } = controller();
  const expected = snapshotOf();
  state.settingsSnapshot = expected;
  host.respond("read_settings_snapshot", snapshotOf({}, { live_status: "not_found", persisted_intent: false, matches_persisted_intent: true }));
  await settings.refreshStartupLoginItemStatus(expected);
  assert.equal(state.launchAtLogin.liveStatus, "not_found");
  assert.equal(d.renderPage.count(), 1);
  host.respond("read_settings_snapshot", new Error("sm unavailable"));
  state.settingsSnapshot = expected;
  state.launchAtLogin = { liveStatus: "checking" };
  await settings.refreshStartupLoginItemStatus(expected);
  assert.match(state.launchAtLogin.observationError, /^macOS Login Item status could not be read/u);
  state.payload.product.operating_system = "windows";
  await settings.refreshStartupLoginItemStatus(expected);
  assert.match(state.launchAtLogin.observationError, /^Windows startup registration could not be read/u);
  state.activePage = "logs";
  await settings.refreshStartupLoginItemStatus(snapshotOf());
  assert.equal(d.renderPage.count(), 3, "another page is not rendered");
  host.respond("read_settings_snapshot", snapshotOf({ theme: "dark" }));
  state.activePage = "settings";
  await settings.refreshStartupLoginItemStatus(snapshotOf());
  assert.notEqual(state.settingsSnapshot.settings.theme, "dark", "a newer snapshot is not overwritten");
});

test("the settings snapshot and its Login Item state are validated field by field", () => {
  assert.deepEqual(normalizeSettingsSnapshot(snapshotOf()), { ...SETTINGS });
  const invalid = [
    [null, /not an object/u], [[], /not an object/u],
    [{ ...snapshotOf(), extra: 1 }, /field set is invalid/u],
    [{ ...snapshotOf(), persisted: "yes" }, /persisted flag/u],
    [{ ...snapshotOf(), settings: null }, /omitted typed preferences/u],
    [{ ...snapshotOf(), settings: { ...SETTINGS, extra: 1 } }, /preference field set is invalid/u],
    [snapshotOf({ theme: "neon" }), /theme is invalid/u],
    [snapshotOf({ font_family: "Comic" }), /font family is invalid/u],
    [snapshotOf({ language: "klingon" }), /display language is invalid/u],
    [{ ...snapshotOf(), resolved_locale: "xx" }, /display language is invalid/u],
    [snapshotOf({ language: "ja" }), /display language is invalid/u],
    [snapshotOf({ silent_start: "no" }), /silent_start is not boolean/u],
  ];
  for (const [value, message] of invalid) assert.throws(() => normalizeSettingsSnapshot(value), message);

  state.payload.product.operating_system = "macos";
  assert.deepEqual(normalizeLaunchAtLoginState(snapshotOf({}, { live_status: "enabled", persisted_intent: false, matches_persisted_intent: false })),
    { persistedIntent: false, liveStatus: "enabled", matchesPersistedIntent: false });
  const loginInvalid = [
    [{ launch_at_login: null }, /omitted the typed Login Item state/u],
    [snapshotOf({}, { extra: 1 }), /field set is invalid/u],
    [snapshotOf({}, { persisted_intent: "no" }), /persisted intent is not boolean/u],
    [snapshotOf({}, { live_status: "weird" }), /live status is invalid/u],
    [snapshotOf({}, { live_status: "registered" }), /does not belong to the current platform/u],
    [snapshotOf({}, { matches_persisted_intent: "yes" }), /synchronization flag is not boolean/u],
    [snapshotOf({}, { persisted_intent: true }), /disagrees with settings/u],
    [snapshotOf({}, { matches_persisted_intent: false }), /disagrees with live status/u],
  ];
  for (const [value, message] of loginInvalid) assert.throws(() => normalizeLaunchAtLoginState(value), message);
  state.payload.product.operating_system = "windows";
  assert.throws(() => normalizeLaunchAtLoginState(snapshotOf({}, { live_status: "enabled", matches_persisted_intent: false })), /current platform/u);
});

test("the Login Item row explains every observed state on each platform", () => {
  const show = (launchAtLogin, os = "macos") => {
    state.payload.product.operating_system = os;
    state.launchAtLogin = launchAtLogin;
    return launchAtLoginPresentation();
  };
  state.settingsUnavailableReason = "store unverifiable";
  assert.deepEqual(show({}), { hint: "store unverifiable", reason: "store unverifiable" });
  state.settingsUnavailableReason = null;
  assert.deepEqual(show({ observationError: "read failed" }), { hint: "read failed", reason: "read failed" });
  assert.match(show({ liveStatus: "checking" }).reason, /Checking macOS Login Item/u);
  assert.match(show({ liveStatus: "checking" }, "windows").reason, /Checking Windows startup/u);
  assert.match(show({ liveStatus: "unknown" }).reason, /unknown Login Item state/u);
  assert.match(show({ liveStatus: "unknown" }, "windows").reason, /could not be verified/u);
  assert.match(show({ liveStatus: "registered", matchesPersistedIntent: true }, "windows").hint, /Registered for this user's sign-in/u);
  assert.match(show({ liveStatus: "registered", matchesPersistedIntent: false }, "windows").hint, /saved preference says Off/u);
  assert.match(show({ liveStatus: "not_registered", matchesPersistedIntent: true }, "windows").hint, /No startup registration/u);
  assert.match(show({ liveStatus: "not_registered", matchesPersistedIntent: false }, "windows").hint, /retries registration/u);
  assert.match(show({ liveStatus: "enabled" }, "windows").reason, /could not be verified/u);
  assert.match(show({ liveStatus: "requires_approval" }).hint, /requires approval/u);
  assert.equal(show({ liveStatus: "requires_approval" }).reason, null);
  assert.match(show({ liveStatus: "enabled", matchesPersistedIntent: false }).hint, /currently enables this Login Item/u);
  assert.match(show({ liveStatus: "not_found", matchesPersistedIntent: false }).hint, /cannot find the signed app/u);
  assert.match(show({ liveStatus: "not_registered", matchesPersistedIntent: false }).hint, /reports it is not registered/u);
  assert.match(show({ liveStatus: "enabled", matchesPersistedIntent: true }).hint, /Enabled by macOS/u);
  assert.match(show({ liveStatus: "not_registered", matchesPersistedIntent: true }).hint, /Disabled by macOS/u);
});

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

test("the platform design and network settings are read or their failure reported", async () => {
  host.respond("current_platform_design", { launchd_strategy: "SMAppService Login Item only" });
  await loadPlatformDesign();
  assert.deepEqual(state.platform, { launchd_strategy: "SMAppService Login Item only" });
  host.respond("current_platform_design", { startup_strategy: "Run key" });
  await loadPlatformDesign();
  assert.equal(state.platform, null, "a design for another platform is refused");
  assert.equal(lastLog().message, "Unable to read the platform design: host startup strategy is invalid");
  host.respond("network_diagnostics", { services: [] });
  await loadNetworkDiagnostics();
  assert.deepEqual(state.networkDiagnostics, { services: [] });
  host.respond("network_diagnostics", new Error("SystemConfiguration denied"));
  await loadNetworkDiagnostics();
  assert.equal(state.networkDiagnostics, null);
  assert.equal(lastLog().message, "Unable to inspect network settings: SystemConfiguration denied");
});

test("the startup settings read can skip the Login Item status", async () => {
  const { settings } = controller();
  host.respond("read_settings_snapshot", snapshotOf());
  await settings.loadSettingsSnapshot(false);
  assert.deepEqual(host.argsOf("read_settings_snapshot"), [{ includeLoginItemStatus: false }]);
});
