// The Settings and General pages while the saved network settings are not the
// ones the engine runs with, which happens once something else than the app
// has changed the settings file. Their controls are held and show what the
// engine runs with, and Reload From Disk shows the saved settings in the form,
// whose Apply puts them in use and leaves the switches as the engine runs them.
import assert from "node:assert/strict";
import test from "node:test";
import {
  PROFILE_ID, appModule, emit, interactiveElement, invocationDetails, querySelectorAllElements, renderPage, responses, state,
} from "./support/render-harness.mjs";
import { readRuntimeSettings, readRuntimeSettingsNotInForce, refuseRuntimeSettingsRead } from "./support/runtime-settings-reads.mjs";

const REASON = "The saved network settings are not the ones in use. Reload From Disk in Settings shows them, and Apply puts them in use.";
// What the host refuses every write with while a legacy cleanup is pending.
const LOCKED = "settings cannot change until the legacy cleanup completes: the unfinished migration fixed the engine settings until then, so finish the legacy cleanup first";
// The file as something else left it: no LAN sharing and no protection.
const RESTORED = Object.freeze({ preferred_mixed_port: null, log_level: "info", tunnel_mtu: 1500, allow_lan: false, lan_proxy: null });
const SWITCHES = ["allowLan", "mainlandChinaDirect", "dnsLeakProtection", "webrtcLeakProtection", "tcpConcurrency"];
const attributes = (html, toggle) => html.match(new RegExp(`<input type="checkbox" data-toggle="${toggle}"([^>]*)\\/>`, "u"))[1];
const configure = (html) => html.match(/<button[^>]*data-action="open-runtime-settings"[^>]*>/u)[0];
/// A switch of the General page: its label, which carries the reason, and its input.
const inline = (html, name, toggle) => html.match(new RegExp(`<label class="inline-switch[^>]*data-switch-name="${name}"[^>]*>\\s*<span[^>]*>[^<]*</span>\\s*<input[^>]*data-toggle="${toggle}"[^>]*>`, "u"))[0];
const writes = () => invocationDetails.filter((entry) => entry.command === "write_runtime_settings_snapshot").map((entry) => entry.args);

/// The engine shares the LAN and runs both protections, and the page has read
/// that. Then the file is found changed. Returns what the engine runs with.
async function restoredBehindTheApp(original) {
  await readRuntimeSettings(original, { allowLan: true, dns_leak_protection: true, webrtc_leak_protection: true });
  const running = responses.read_runtime_settings_snapshot;
  await readRuntimeSettingsNotInForce(running, RESTORED, "restored");
  return running;
}

/// The host applies what is written to it and answers every later read with it.
function hostApplies(original) {
  responses.write_runtime_settings_snapshot = (args) => {
    const lan = args.settings.allow_lan ? args.settings.lan_proxy : null;
    responses.read_runtime_settings_snapshot = { ...original, settings: args.settings, revision: "applied", in_force: true,
      effective: { ...original.effective, lan_proxy: lan, mainland_china_direct: args.settings.mainland_china_direct === true,
        dns_leak_protection: args.settings.dns_leak_protection === true, webrtc_leak_protection: args.settings.webrtc_leak_protection === true,
        tcp_concurrency: args.settings.tcp_concurrency !== false } };
    return structuredClone(responses.read_runtime_settings_snapshot);
  };
}

async function withHost(body) {
  const original = responses.read_runtime_settings_snapshot;
  const hadWrite = Object.hasOwn(responses, "write_runtime_settings_snapshot");
  const previousWrite = responses.write_runtime_settings_snapshot;
  try {
    await body(original);
  } finally {
    if (hadWrite) responses.write_runtime_settings_snapshot = previousWrite;
    else delete responses.write_runtime_settings_snapshot;
    querySelectorAllElements.delete("[data-toggle]");
    querySelectorAllElements.delete("[data-runtime-save]");
    state.runtimeSettingsDialog = null;
    await readRuntimeSettings(original);
  }
}

test("both pages hold the engine controls on saved settings that are not in force, and show what the engine runs with", () => withHost(async (original) => {
  await restoredBehindTheApp(original);
  const settings = await renderPage("settings");
  for (const toggle of SWITCHES) {
    assert.match(attributes(settings, toggle), /disabled/u, toggle);
    assert.ok(attributes(settings, toggle).includes(`title="${REASON}"`), toggle);
  }
  // What the engine runs with, not what the file says.
  assert.deepEqual(SWITCHES.map((toggle) => /checked/u.test(attributes(settings, toggle))), [true, false, true, true, true]);
  assert.match(configure(settings), /disabled/u);
  assert.ok(configure(settings).includes(`title="${REASON}"`));
  assert.ok(settings.includes(`<small>${REASON}</small>`), "the reason stands beside the control");

  const general = await renderPage("general");
  for (const [name, toggle] of [["Allow LAN", "allowLan"], ["IPv6 DNS", "ipv6DNS"]]) {
    assert.match(inline(general, name, toggle), /<input[^>]* disabled/u, name);
    assert.ok(inline(general, name, toggle).includes(`title="${REASON}"`), name);
    assert.match(inline(general, name, toggle), /<input[^>]* checked/u, name);
  }
  assert.ok(general.includes("Bind: 0.0.0.0:7898"), "the listener the engine has, which the file no longer names");
  assert.match(configure(general), /disabled/u);
  assert.match(general.match(/<select class="cfw-select" data-runtime-log-level([^>]*)>/u)[1], /disabled/u);
  // The file says nothing of the engine's port now, so the row names no
  // policy for it, and its button carries the reason.
  assert.doesNotMatch(general, /Automatic port|Configured port|data-action="open-runtime-settings"[^>]*>[^<]*<\/button>\s*<small/u);
  assert.ok(configure(general).includes(`title="${REASON}"`));
}));

test("Reload From Disk shows the saved settings, and their Apply puts them in use, keeps the switches and frees the controls", () => withHost(async (original) => {
  await restoredBehindTheApp(original);
  hostApplies(original);
  const applyButton = interactiveElement("button");
  querySelectorAllElements.set("[data-runtime-save]", [applyButton]);
  await renderPage("settings");
  invocationDetails.length = 0;
  await appModule.handleAction("reload-settings");
  assert.deepEqual(writes(), [], "the reload changes nothing of the network by itself");
  const dialog = state.runtimeSettingsDialog;
  assert.deepEqual([dialog.revision, dialog.basis.in_force, dialog.draft.allow], ["restored", false, false]);
  assert.ok(state.logs.map((entry) => entry.message).includes("Preferences reloaded from disk"));
  // The controls stay held until the saved settings are applied.
  let settings = await renderPage("settings");
  for (const toggle of SWITCHES) assert.match(attributes(settings, toggle), /disabled/u, toggle);
  await applyButton.trigger("click");
  // The form does not show the two protections, so they stay as the engine
  // runs them, though the file has neither.
  assert.deepEqual(writes(), [{ settings: { ...RESTORED, dns_leak_protection: true, webrtc_leak_protection: true }, revision: "restored", basis: { in_force: false, saved_ipv6_dns_enabled: true } }]);
  assert.equal(state.runtimeSettingsDialog, null);
  assert.ok(state.logs.map((entry) => entry.message).includes("Runtime settings applied and saved"));
  settings = await renderPage("settings");
  for (const toggle of SWITCHES) assert.doesNotMatch(attributes(settings, toggle), /disabled|title=/u, toggle);
  // The saved settings are in force now, and the page shows them.
  assert.deepEqual(SWITCHES.map((toggle) => /checked/u.test(attributes(settings, toggle))), [false, false, true, true, true]);
  const general = await renderPage("general");
  assert.match(general, /<small class="cfw-row-note" title="[^"]*">Automatic port<\/small>/u);
  assert.doesNotMatch(configure(settings), /disabled/u);
  assert.equal(state.engineMutationBusy, false);
}));

test("a click on a page that has not read the changed file writes nothing, and the page then holds the controls", () => withHost(async (original) => {
  await readRuntimeSettings(original, { allowLan: true, dns_leak_protection: true, webrtc_leak_protection: true });
  const running = responses.read_runtime_settings_snapshot;
  hostApplies(original);
  const input = interactiveElement("input");
  input.dataset.toggle = "mainlandChinaDirect";
  querySelectorAllElements.set("[data-toggle]", [input]);
  let settings = await renderPage("settings");
  assert.doesNotMatch(attributes(settings, "dnsLeakProtection"), /disabled/u);
  // The file changes behind the page, which still shows free controls.
  responses.read_runtime_settings_snapshot = { ...running, settings: RESTORED, revision: "restored", in_force: false };
  invocationDetails.length = 0;
  input.checked = true;
  await input.trigger("change");
  assert.deepEqual(writes(), [], "the click would have applied the rest of the file with it");
  assert.equal(state.logs[0].message, `mainlandChinaDirect refused: ${REASON}`);
  settings = await renderPage("settings");
  for (const toggle of SWITCHES) assert.match(attributes(settings, toggle), /disabled/u, toggle);
  assert.match(attributes(settings, "dnsLeakProtection"), /checked/u, "the protection is still on, and shown on");
  assert.doesNotMatch(attributes(settings, "mainlandChinaDirect"), /checked/u);
}));

test("General names a policy for the port only from saved settings that are known and in force", () => withHost(async (original) => {
  // The note that follows the button of the port, where there is one.
  const policy = (html) => html.match(/data-action="open-runtime-settings"[^>]*>[^<]*<\/button>\s*<small class="cfw-row-note" title="[^"]*">([^<]*)<\/small>/u)?.[1] ?? null;
  await readRuntimeSettings(original);
  let general = await renderPage("general");
  assert.equal(policy(general), "Automatic port");
  assert.doesNotMatch(configure(general), /disabled|title=/u);
  // The file keeps the port the engine listens on.
  await readRuntimeSettings({ ...original, settings: { ...original.settings, preferred_mixed_port: 7890 } });
  assert.equal(policy(await renderPage("general")), "Configured port");
  // A read that fails leaves the page the settings it had, and those no
  // longer say what the engine does: the row names no policy, and its
  // button carries the failure.
  await refuseRuntimeSettingsRead("runtime settings unavailable");
  general = await renderPage("general");
  assert.equal(policy(general), null);
  assert.doesNotMatch(general, /Automatic port|Configured port/u);
  assert.match(configure(general), /disabled/u);
  assert.ok(configure(general).includes('title="runtime settings unavailable"'));
}));

test("Reload From Disk opens no form over another dialog of the app", () => withHost(async (original) => {
  await restoredBehindTheApp(original);
  await renderPage("settings");
  const hadRules = Object.hasOwn(responses, "read_automation_settings");
  const previousRules = responses.read_automation_settings;
  responses.read_automation_settings = { settings: { shortcuts: [], network_enabled: false, network_rules: [] }, revision: "kept", network: null };
  try {
    // The dialog of the shortcuts and network rules, with something entered.
    await appModule.handleAction("open-automation-settings");
    const rules = state.automationDialog;
    rules.draft.shortcuts.toggle_core = "Control+Shift+P";
    await appModule.handleAction("reload-settings");
    assert.equal(state.automationDialog, rules);
    assert.equal(rules.draft.shortcuts.toggle_core, "Control+Shift+P");
    assert.equal(state.runtimeSettingsDialog, null);
    state.automationDialog = null;
    // A confirmation, and the menu of a profile.
    for (const [slot, open] of [["glassDialog", { kind: "reset-settings" }], ["profileContextMenu", { id: PROFILE_ID, x: 1, y: 1 }]]) {
      state[slot] = open;
      await appModule.handleAction("reload-settings");
      assert.equal(state[slot], open, slot);
      assert.equal(state.runtimeSettingsDialog, null, slot);
      state[slot] = null;
    }
    // With none of them open, the form opens.
    await appModule.handleAction("reload-settings");
    assert.equal(state.runtimeSettingsDialog.basis.in_force, false);
    state.runtimeSettingsDialog = null;
    // The reload is pressed, and the shortcuts and network rules are asked
    // for while it reads. Its read ends first: the form would close the
    // dialog that was asked for last, before that one had opened.
    const held = { settings: responses.read_runtime_settings_snapshot, rules: responses.read_automation_settings };
    const answers = {};
    responses.read_runtime_settings_snapshot = () => new Promise((resolve) => { answers.settings = resolve; });
    responses.read_automation_settings = () => new Promise((resolve) => { answers.rules = resolve; });
    const reloaded = appModule.handleAction("reload-settings");
    const wanted = appModule.handleAction("open-automation-settings");
    responses.read_runtime_settings_snapshot = held.settings;
    answers.settings(held.settings);
    await reloaded;
    assert.equal(state.runtimeSettingsDialog, null);
    answers.rules(held.rules);
    await wanted;
    assert.equal(state.automationDialog.snapshot.revision, "kept", "the dialog that was asked for last opens");
    assert.equal(state.runtimeSettingsDialog, null);
  } finally {
    state.automationDialog = null;
    state.glassDialog = null;
    state.profileContextMenu = null;
    if (hadRules) responses.read_automation_settings = previousRules;
    else delete responses.read_automation_settings;
  }
}));

test("Reload From Disk opens no form once a dialog that reads first was asked for after it", () => withHost(async (original) => {
  await restoredBehindTheApp(original);
  await renderPage("settings");
  const hadPreview = Object.hasOwn(responses, "preview_credential_gc");
  const previousPreview = responses.preview_credential_gc;
  const settings = responses.read_runtime_settings_snapshot;
  const unused = { preview_id: "8f14e45f-ceea-4670-a91e-2f0f1d5e6a7b", orphan_count: 0, orphan_references: [] };
  const answers = {};
  const hold = () => {
    responses.read_runtime_settings_snapshot = () => new Promise((resolve) => { answers.settings = () => resolve(settings); });
    responses.preview_credential_gc = () => new Promise((resolve) => { answers.preview = () => resolve(unused); });
  };
  try {
    // The reload is pressed, and the review of unused credentials is asked
    // for while it reads. Whichever read ends first, the review opens, and
    // no form opens before it or beside it.
    for (const first of ["settings", "preview"]) {
      hold();
      const reloaded = appModule.handleAction("reload-settings");
      const wanted = appModule.handleAction("preview-credential-gc");
      responses.read_runtime_settings_snapshot = settings;
      answers[first]();
      await (first === "settings" ? reloaded : wanted);
      assert.equal(state.runtimeSettingsDialog, null, `${first} answers first: no form`);
      answers[first === "settings" ? "preview" : "settings"]();
      await Promise.all([reloaded, wanted]);
      assert.equal(state.glassDialog?.kind, "credential-cleanup", `${first} answers first: the dialog that was asked for last opens`);
      assert.equal(state.runtimeSettingsDialog, null, `${first} answers first: and no form beside it`);
      state.glassDialog = null;
    }
    // The review is asked for, and the reload is pressed while it reads. The
    // reload asks for the form once it has saved settings to show, so the
    // review, which was asked for before that, opens nothing over the form.
    hold();
    const wanted = appModule.handleAction("preview-credential-gc");
    const reloaded = appModule.handleAction("reload-settings");
    responses.read_runtime_settings_snapshot = settings;
    answers.settings();
    await reloaded;
    const form = state.runtimeSettingsDialog;
    assert.equal(form.basis.in_force, false);
    answers.preview();
    await wanted;
    assert.equal(state.runtimeSettingsDialog, form);
    assert.equal(state.glassDialog, null, "the review that was overtaken opens nothing over the form");
  } finally {
    state.glassDialog = null;
    state.runtimeSettingsDialog = null;
    state.credentialGcPreview = null;
    responses.read_runtime_settings_snapshot = settings;
    if (hadPreview) responses.preview_credential_gc = previousPreview;
    else delete responses.preview_credential_gc;
  }
}));

test("while no change can be made, both pages say that in place of the advice, and the reload offers no form", () => withHost(async (original) => {
  await restoredBehindTheApp(original);
  responses.read_runtime_settings_snapshot = { ...responses.read_runtime_settings_snapshot, change_refused: LOCKED };
  await emit("cfw://settings-changed", responses.read_settings_snapshot);
  const settings = await renderPage("settings");
  for (const toggle of SWITCHES) {
    assert.match(attributes(settings, toggle), /disabled/u, toggle);
    assert.ok(attributes(settings, toggle).includes(`title="${LOCKED}"`), toggle);
  }
  assert.ok(configure(settings).includes(`title="${LOCKED}"`));
  assert.ok(settings.includes(`<small>${LOCKED}</small>`), "the reason stands beside the control");
  assert.equal(settings.includes(REASON), false, "no advice that could not be followed");
  const general = await renderPage("general");
  for (const [name, toggle] of [["Allow LAN", "allowLan"], ["IPv6 DNS", "ipv6DNS"]]) assert.ok(inline(general, name, toggle).includes(`title="${LOCKED}"`), name);
  assert.ok(configure(general).includes(`title="${LOCKED}"`));
  assert.equal(general.includes(REASON), false);
  invocationDetails.length = 0;
  await renderPage("settings");
  await appModule.handleAction("reload-settings");
  assert.equal(state.runtimeSettingsDialog, null);
  assert.deepEqual(writes(), []);
  // The cleanup completes, and the next reload shows the saved settings.
  responses.read_runtime_settings_snapshot = { ...responses.read_runtime_settings_snapshot, change_refused: null };
  await appModule.handleAction("reload-settings");
  assert.equal(state.runtimeSettingsDialog.basis.in_force, false);
  assert.ok((await renderPage("settings")).includes(REASON));
}));
