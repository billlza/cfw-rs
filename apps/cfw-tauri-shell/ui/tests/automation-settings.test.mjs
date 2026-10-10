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
  const state = {};
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
