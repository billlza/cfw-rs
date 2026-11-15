// The settings store and form: applied snapshots, refused values, saving,
// reloading and resetting, appearance changes, the Login Item state, and the
// startup and platform reads.
import { dom, element, host, spy } from "./support/fake-host.mjs";
import assert from "node:assert/strict";
import { test } from "node:test";
import { state, defaultSettingsSnapshot } from "../src/state.js";
import { setLocale } from "../src/i18n.js";
import { createSettingsController } from "../src/settings-controller.js";
import { loadNetworkDiagnostics, loadPlatformDesign } from "../src/system-info.js";
import {
  launchAtLoginPresentation, normalizeLaunchAtLoginState, normalizeSettingsSnapshot,
} from "../src/settings-snapshot.js";
import {
  SETTINGS, lastLog, messages, snapshotOf,
} from "./support/settings-engine-harness.mjs";

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

test("a failed Login Item read is reported in the display language", async () => {
  const { settings } = controller();
  const expected = snapshotOf();
  const system = state.payload.product.operating_system;
  const sentences = {
    macos: {
      "zh-Hans": "无法读取 macOS 登录项状态。请重新加载后重试；失败已记录在本地诊断中。",
      "zh-Hant": "無法讀取 macOS 登入項目狀態。請重新載入後重試；失敗已記錄於本機診斷中。",
      ja: "macOS のログイン項目の状態を読み取れませんでした。再読み込みして再試行してください。エラーはローカル診断に記録されています。",
    },
    windows: {
      "zh-Hans": "无法读取 Windows 启动注册。请重新加载后重试；失败已记录在本地诊断中。",
      "zh-Hant": "無法讀取 Windows 啟動註冊。請重新載入後重試；失敗已記錄於本機診斷中。",
      ja: "Windows の起動登録を読み取れませんでした。再読み込みして再試行してください。エラーはローカル診断に記録されています。",
    },
  };
  try {
    host.respond("read_settings_snapshot", new Error("sm unavailable"));
    for (const [operatingSystem, translated] of Object.entries(sentences)) {
      state.payload.product.operating_system = operatingSystem;
      for (const [locale, sentence] of Object.entries(translated)) {
        setLocale(locale);
        state.settingsSnapshot = expected;
        await settings.refreshStartupLoginItemStatus(expected);
        assert.equal(state.launchAtLogin.observationError, sentence, `${operatingSystem} ${locale}`);
        assert.equal(lastLog().message, sentence, `${operatingSystem} ${locale}: the log line is the same sentence`);
      }
    }
  } finally {
    setLocale("en");
    state.payload.product.operating_system = system;
  }
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
