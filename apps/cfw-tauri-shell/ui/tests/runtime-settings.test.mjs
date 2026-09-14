import test from "node:test";
import assert from "node:assert/strict";
import { createRuntimeSettingsUI, preferencesFromRuntimeDraft, runtimeDraft } from "../src/runtime-settings.js";

const preferences = { preferred_mixed_port:null, log_level:"info", tunnel_mtu:1500, allow_lan:false, lan_proxy:null };
const response = () => ({ settings:structuredClone(preferences), revision:null, effective:{mixed_port:7890,log_level:"info",tunnel_mtu:1500,lan_proxy:null} });

test("runtime drafts require an explicit LAN scope and preserve automatic port selection", () => {
  const draft = runtimeDraft(preferences);
  assert.deepEqual(preferencesFromRuntimeDraft(draft), preferences);
  draft.allow = true;
  assert.throws(() => preferencesFromRuntimeDraft(draft), /trusted LAN source ranges/u);
  draft.lanSources = "192.168.1.0/24";
  assert.equal(preferencesFromRuntimeDraft(draft).lan_proxy.listen, "0.0.0.0");
  draft.port = "80";
  assert.throws(() => preferencesFromRuntimeDraft(draft), /Proxy port/u);
  draft.port = "7898";
  assert.throws(() => preferencesFromRuntimeDraft(draft), /must be different/u);
  draft.port = "8890"; draft.mtu = "99999";
  assert.throws(() => preferencesFromRuntimeDraft(draft), /MTU/u);
});

test("opening LAN settings while Off does not start or change the engine", async () => {
  const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
  const calls = [];
  const ui = createRuntimeSettingsUI({state,invoke:async (command) => {calls.push(command);return response();},appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
  await ui.toggleLAN(true);
  assert.deepEqual(calls, ["read_runtime_settings_snapshot"]);
  assert.equal(state.runtimeSettingsDialog.draft.allow, true);
  assert.equal(state.toggles.allowLan, false, "opening a form is not applying LAN sharing");
  assert.equal(state.runtimeSettingsDialog.draft.lanSources, "");
});

test("a rejected settings transaction retains the saved values and refreshes actual runtime state", async () => {
  const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
  let refreshed = 0;
  let submitted;
  const messages = [];
  const ui = createRuntimeSettingsUI({state,invoke:async (command, args) => {
    if(command === "write_runtime_settings_snapshot") {submitted=args;throw new Error("settings changed");}
    return response();
  },appendLog(...args){messages.push(args);},renderPage(){},refreshRuntime(){refreshed++;},dismissOtherDialogs(){}});
  await ui.open();
  const dialog = state.runtimeSettingsDialog;
  dialog.draft.level = "debug";
  assert.equal(await ui.save(preferencesFromRuntimeDraft(dialog.draft), "old-revision", dialog), false);
  assert.equal(submitted.revision, "old-revision");
  assert.equal(state.runtimeSettings.settings.log_level, "info");
  assert.equal(dialog.draft.level, "debug", "a failed save preserves the editable draft");
  assert.equal(dialog.error, "settings changed");
  assert.equal(refreshed, 1);
  assert.equal(state.engineMutationBusy, false);
  assert.ok(messages.some(([level]) => level === "error"));
});
