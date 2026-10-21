import test from "node:test";
import assert from "node:assert/strict";
import { createAutomationSettingsUI, automationDraft, preferencesFromAutomationDraft } from "../src/automation-settings.js";

test("automation defaults do not register shortcuts or enable network changes", () => {
  const preferences = { shortcuts: [], network_enabled: false, network_rules: [] };
  const draft = automationDraft(preferences);
  assert.deepEqual(preferencesFromAutomationDraft(draft), preferences);
  draft.enabled = true;
  assert.throws(() => preferencesFromAutomationDraft(draft), /Add a network rule/);
  draft.rules.push({ network: { type: "ssid", name: "Home " }, mode: "tunnel" });
  assert.equal(preferencesFromAutomationDraft(draft).network_rules[0].network.name, "Home ", "SSID whitespace is meaningful");
  draft.shortcuts.toggle_core = "Control+Shift+P";
  assert.equal(preferencesFromAutomationDraft(draft).shortcuts[0].action, "toggle_core");
});

test("registration conflicts keep the automation dialog and the exact user draft", async () => {
  const state = { payload: { product: { operating_system: "macos" } } };
  const calls = [];
  const ui = createAutomationSettingsUI({ state, renderPage: () => {}, appendLog: () => {}, dismissOtherDialogs: () => {},
    invoke: async (command) => {
      calls.push(command);
      if (command === "read_automation_settings") return { settings: { shortcuts: [], network_enabled: false, network_rules: [] }, revision: "old", network: { kind: "wifi", interface: "en0", ssid: null } };
      throw new Error("shortcut occupied");
    } });
  await ui.open();
  assert.deepEqual(calls, ["read_automation_settings"]);
  assert.match(ui.renderDialog(), /macOS is not providing the Wi-Fi name/);
  state.automationDialog.draft.shortcuts.show_dashboard = "Command+Option+P";
  await ui.save();
  assert.equal(state.automationDialog.draft.shortcuts.show_dashboard, "Command+Option+P");
  assert.equal(state.automationDialog.error, "shortcut occupied");
  assert.equal(state.automationDialog.saving, false);
});

test("a refused Windows SSID observation still exposes the native Location settings action", async () => {
  const state = { payload: { product: { operating_system: "windows" } } };
  const calls = [];
  const handlers = new Map();
  const originalDocument = globalThis.document;
  const snapshot = { settings: { shortcuts: [], network_enabled: false, network_rules: [] },
    revision: null, network: null, network_error: "Wi-Fi name access was denied" };
  const ui = createAutomationSettingsUI({ state, renderPage: () => {}, appendLog: () => {}, dismissOtherDialogs: () => {},
    invoke: async (command) => {
      calls.push(command);
      if (command === "read_automation_settings") return structuredClone(snapshot);
      if (command === "request_wifi_name_access") return null;
      throw new Error(`Unexpected command: ${command}`);
    } });
  try {
    await ui.open();
    const html = ui.renderDialog();
    assert.match(html, /Wi-Fi name access was denied/u);
    assert.match(html, /data-wifi-permission/u);
    assert.match(html, /Open Windows Location settings/u);
    assert.match(html, /Control\+Alt\+P/u);
    assert.doesNotMatch(html, /macOS|Command\+Option|CFM/u);
    globalThis.document = { querySelectorAll: (selector) => selector === "[data-wifi-permission]"
      ? [{ addEventListener: (event, handler) => handlers.set(event, handler) }] : [] };
    ui.bindDialog();
    handlers.get("click")();
    await new Promise(setImmediate);
    assert.deepEqual(calls, ["read_automation_settings", "request_wifi_name_access"]);
    assert.equal(state.automationDialog.notice, "Review Windows Location settings, then refresh network status.");
    assert.equal(state.automationDialog.snapshot.network_error, snapshot.network_error);
    assert.equal(state.automationDialog.snapshot.network, null);
    assert.deepEqual(preferencesFromAutomationDraft(state.automationDialog.draft), snapshot.settings);
    state.automationDialog.snapshot.network_error = null;
    assert.doesNotMatch(ui.renderDialog(), /data-wifi-permission/u, "no active network is not a permission failure");
  } finally {
    if (originalDocument === undefined) delete globalThis.document;
    else globalThis.document = originalDocument;
  }
});
