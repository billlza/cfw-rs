// General page and engine actions: copied proxy commands, the info dialog,
// folders and settings pages, engine retries, TUN approval, and the fake-IP
// cache.
import { clipboard, dom, element, host, spy } from "./support/fake-host.mjs";
import { replaceEngineIdentity, runEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { test } from "node:test";
import { state } from "../src/state.js";
import { createGeneralActions } from "../src/general-actions.js";
import { createEngineActions } from "../src/engine-actions.js";
import {
  lastLog,
} from "./support/settings-engine-harness.mjs";

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
