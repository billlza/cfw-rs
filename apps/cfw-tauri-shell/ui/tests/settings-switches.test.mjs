// Switches: runtime settings switches, network switches that are refused,
// superseded or restored, and preferences against session switches.
import { host, settle, spy } from "./support/fake-host.mjs";
import { runEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { test } from "node:test";
import { state, runtime } from "../src/state.js";
import { setLocale } from "../src/i18n.js";
import { createToggles } from "../src/toggles.js";
import { readNetworkDiagnostics } from "../src/system-info.js";
import { outcome } from "./support/outcome.mjs";
import {
  SETTINGS, lastLog, snapshotOf,
} from "./support/settings-engine-harness.mjs";

function toggleDeps(overrides = {}) {
  return {
    renderPage: spy(),
    scheduleLogStreamPatch: spy(),
    runtimeSettingsUI: {
      toggleLAN: spy(async () => "lan"), toggleIPv6DNS: spy(async () => "ipv6"),
      toggleMainlandChinaDirect: spy(async () => "cn"), toggleDnsLeakProtection: spy(async () => "dns"),
      toggleWebRtcLeakProtection: spy(async () => "webrtc"), toggleTcpConcurrency: spy(async () => "tcp"),
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
  assert.equal(await applyToggle("webrtcLeakProtection", true), "webrtc");
  assert.equal(await applyToggle("tcpConcurrency", false), "tcp");
  assert.deepEqual(d.runtimeSettingsUI.toggleTcpConcurrency.calls, [[false]]);
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
  setLocale("zh-Hans");
  try {
    await assert.rejects(() => applyToggle("systemProxy", true, "ui"), { message: "网络模式正在切换中" });
  } finally { setLocale("en"); }
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

test("a stored switch reports its new state in the display language", async () => {
  const { applyToggle } = createToggles(toggleDeps());
  host.respond("write_settings_snapshot", snapshotOf({ silent_start: true }));
  await applyToggle("silentStart", true, "ui");
  assert.equal(lastLog().message, "silentStart changed to on");
  setLocale("zh-Hans");
  try {
    host.respond("write_settings_snapshot", snapshotOf({ silent_start: false }));
    await applyToggle("silentStart", false, "ui");
    assert.equal(lastLog().message, "silentStart已更改为关闭");
    host.respond("write_settings_snapshot", snapshotOf({ silent_start: true }));
    await applyToggle("silentStart", true, "ui");
    assert.equal(lastLog().message, "silentStart已更改为开启");
  } finally { setLocale("en"); }
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
  setLocale("zh-Hans");
  try {
    await applyToggle("breakOnProxyChange", false, "ui");
    assert.equal(lastLog().message, "本次运行的breakOnProxyChange已更改为关闭", "the state is named in the display language");
    await applyToggle("breakOnProxyChange", true, "ui");
    assert.equal(lastLog().message, "本次运行的breakOnProxyChange已更改为开启");
  } finally { setLocale("en"); }
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

test("a press of System Proxy ends, and frees the switches of the modes, before the network settings are observed again", async () => {
  state.engine = { ...state.engine, active: false, systemProxyAvailable: true, localProxyAvailable: true, tunnelAvailable: true };
  const page = state.activePage;
  state.activePage = "settings";
  const d = toggleDeps();
  const { applyUiToggle } = createToggles(d);
  const observed = (name) => ({ default_route_interface: name, service_order: [], services: [] });
  const answers = [];
  host.respond("network_diagnostics", () => new Promise((resolve) => { answers.push(resolve); }));
  host.respond("set_system_proxy_enabled", { mode: "system_proxy" });
  try {
    // An observation is under way, the one at startup for one.
    const under = readNetworkDiagnostics();
    await settle();
    // A native switch of General takes no other click until its press has ended.
    const pressed = applyUiToggle("systemProxy", true);
    await settle();
    assert.equal(state.engineMutationBusy, false, "the switches of the modes are free while the observation is under way");
    assert.equal(await outcome(pressed), undefined, "the press ends without waiting for the observation");
    assert.match(lastLog().message, /^systemProxy request completed/u);
    answers.shift()(observed("en0"));
    assert.equal((await outcome(under)).default_route_interface, "en0");
    await settle();
    const drawn = d.renderPage.count();
    // The next observation sees what the change left.
    answers.shift()(observed("en1"));
    await settle();
    assert.equal(state.networkDiagnostics.default_route_interface, "en1");
    assert.ok(d.renderPage.count() > drawn, "Settings shows what the next observation found");
  } finally {
    state.activePage = page;
  }
});

test("a change of the system proxy observes the network settings once the host made it, and draws them only on Settings", async () => {
  state.engine = { ...state.engine, active: false, systemProxyAvailable: true, localProxyAvailable: true, tunnelAvailable: true };
  const page = state.activePage;
  state.activePage = "general";
  const d = toggleDeps({ loadEngineStatus: spy(async () => { throw new Error("status unreadable"); }) });
  const { applyToggle } = createToggles(d);
  const answers = [];
  host.respond("network_diagnostics", () => new Promise((resolve) => { answers.push(resolve); }));
  try {
    host.respond("set_system_proxy_enabled", new Error("refused"));
    const refused = assert.rejects(applyToggle("systemProxy", true, "ui"), /refused/u);
    await settle();
    assert.equal(answers.length, 0, "a change the host refused observes nothing");
    assert.equal(await outcome(refused), undefined, "and it ends with the refusal");
    // The status the host answers is overtaken, and reading it again fails.
    host.respond("set_system_proxy_enabled", () => { runtime.engineStatusRequestId += 1; return {}; });
    const failed = assert.rejects(applyToggle("systemProxy", true, "ui"), /status unreadable/u);
    await settle();
    assert.equal(await outcome(failed), undefined, "it ends with that failure without waiting for the observation");
    assert.equal(answers.length, 1, "a change the host made is observed although it failed after");
    const drawn = d.renderPage.count();
    answers.shift()({ default_route_interface: "en2", service_order: [], services: [] });
    await settle();
    assert.equal(state.networkDiagnostics.default_route_interface, "en2");
    assert.equal(d.renderPage.count(), drawn, "another page is not drawn for what it found");
  } finally {
    state.activePage = page;
  }
});

test("a failure to observe the network settings after a change of the system proxy is drawn on the Logs page while it is open", async () => {
  state.engine = { ...state.engine, active: false, systemProxyAvailable: true, localProxyAvailable: true, tunnelAvailable: true };
  const page = state.activePage;
  const d = toggleDeps();
  const { applyUiToggle } = createToggles(d);
  host.respond("set_system_proxy_enabled", { mode: "system_proxy" });
  const press = async (where, answer) => {
    state.activePage = where;
    host.respond("network_diagnostics", answer);
    const pressed = applyUiToggle("systemProxy", true);
    await settle();
    assert.equal(await outcome(pressed), undefined, `the press ends on ${where}`);
  };
  try {
    await press("general", new Error("no answer"));
    assert.equal(lastLog().message, "Unable to inspect network settings: no answer");
    assert.equal(d.scheduleLogStreamPatch.count(), 0, "a page that shows no log is not drawn for it");
    await press("logs", new Error("no answer"));
    assert.equal(lastLog().message, "Unable to inspect network settings: no answer");
    assert.equal(d.scheduleLogStreamPatch.count(), 1, "the Logs page shows the failure, which came after the press had ended");
    await press("logs", { default_route_interface: "en3", service_order: [], services: [] });
    assert.equal(state.networkDiagnostics.default_route_interface, "en3");
    assert.match(lastLog().message, /^systemProxy request completed/u);
    assert.equal(d.scheduleLogStreamPatch.count(), 1, "an observation that read logs nothing, and the Logs page is not drawn for it");
  } finally {
    state.activePage = page;
  }
});
