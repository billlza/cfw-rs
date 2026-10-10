import test from "node:test";
import assert from "node:assert/strict";
import { acceptNativeRuntimeDraft, createRuntimeSettingsUI, preferencesFromRuntimeDraft, runtimeDraft } from "../src/runtime-settings.js";

const preferences = { preferred_mixed_port:null, log_level:"info", tunnel_mtu:1500, allow_lan:false, lan_proxy:null };
const response = () => ({ settings:structuredClone(preferences), revision:null, effective:{mixed_port:7890,log_level:"info",tunnel_mtu:1500,ipv6_dns_enabled:true,lan_proxy:null} });

function nativeDraft(draft, edits = {}) {
  const { initialIPv6DNS, ipv6DNSInherited, ...fields } = draft;
  return { ...fields, ipv6DNSEdited: !ipv6DNSInherited, ...edits };
}

test("native form retains inherited IPv6 unless explicitly touched and rejects expanded drafts", () => {
  const prior = runtimeDraft(preferences, { ipv6_dns_enabled: false });
  const retained = acceptNativeRuntimeDraft(prior, nativeDraft(prior, { level: "debug" }));
  assert.equal(Object.hasOwn(preferencesFromRuntimeDraft(retained), "ipv6_dns_enabled"), false);
  const touched = acceptNativeRuntimeDraft(prior, nativeDraft(prior, { ipv6DNSEdited: true }));
  assert.equal(preferencesFromRuntimeDraft(touched).ipv6_dns_enabled, false, "choosing then reverting is still explicit");
  for (const invalid of [
    { ...nativeDraft(prior), revision: "forged" },
    nativeDraft(prior, { ipv6DNS: "false" }), nativeDraft(prior, { ipv6DNSEdited: 1 }),
    nativeDraft(prior, { level: "other" }), nativeDraft(prior, { lanSources: "x".repeat(8193) }),
  ]) assert.throws(() => acceptNativeRuntimeDraft(prior, invalid), /draft is invalid/u);
});

test("native settings submit uses the unchanged LAN validation, save revision and retained failure draft", async () => {
  globalThis.document = { documentElement: { dataset: { theme: "dark" } } };
  const state = { toggles: {}, engineMutationBusy: false, migrationHandoff: false };
  const writes = [], frames = [];
  let callbacks, rejectWrite, signalWrite;
  const started = new Promise((resolve) => { signalWrite = resolve; });
  const ui = createRuntimeSettingsUI({ state,
    invoke: async (command, args) => {
      if (command === "read_runtime_settings_snapshot") return { ...response(), revision: "original" };
      assert.equal(command, "write_runtime_settings_snapshot");
      writes.push(args); signalWrite();
      await new Promise((_, reject) => { rejectWrite = reject; });
    },
    nativeDialog: { enabled: () => true, sync: (dialog, frame, handlers) => { frames.push(frame); callbacks = handlers; return null; } },
    appendLog() {}, renderPage() {}, refreshRuntime() {}, dismissOtherDialogs() {},
  });
  await ui.open(true);
  const dialog = state.runtimeSettingsDialog;
  assert.match(ui.renderDialog(), /data-runtime-dismiss/u);
  assert.equal(frames.at(-1).appearance, "dark");
  await callbacks.onSubmit(nativeDraft(dialog.draft));
  assert.equal(writes.length, 0, "opening native controls cannot grant LAN access");
  assert.match(dialog.error, /trusted LAN source ranges/u);
  const submitted = nativeDraft(dialog.draft, { lanSources: "192.168.1.0/24", port: "8990" });
  const saving = callbacks.onSubmit(submitted);
  await started;
  assert.equal(dialog.saving, true);
  ui.close(); assert.equal(state.runtimeSettingsDialog, dialog);
  assert.equal(writes[0].revision, "original");
  assert.equal(writes[0].settings.preferred_mixed_port, 8990);
  rejectWrite(new Error("revision conflict"));
  await saving;
  assert.equal(state.runtimeSettingsDialog, dialog);
  assert.equal(dialog.saving, false);
  assert.equal(dialog.draft.port, "8990");
  assert.match(dialog.error, /revision conflict/u);
});

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

test("IPv6 DNS is configurable without silently changing old preferences", () => {
  const draft = runtimeDraft(preferences);
  assert.equal(draft.ipv6DNS, true);
  draft.ipv6DNS = false;
  assert.equal(preferencesFromRuntimeDraft(draft).ipv6_dns_enabled, false);
  assert.equal(runtimeDraft({ ...preferences, ipv6_dns_enabled:false }).ipv6DNS, false);
  draft.ipv6DNS = "false";
  assert.throws(() => preferencesFromRuntimeDraft(draft), /IPv6 DNS/u);
});

test("unrelated settings preserve inherited DNS while an explicit IPv6 choice is retained", () => {
  const draft = runtimeDraft(preferences, { ipv6_dns_enabled:false });
  assert.equal(draft.ipv6DNS, false, "the editor displays the imported policy actually in use");
  draft.level = "debug";
  assert.equal(Object.hasOwn(preferencesFromRuntimeDraft(draft), "ipv6_dns_enabled"), false);
  draft.ipv6DNS = true;
  assert.equal(preferencesFromRuntimeDraft(draft).ipv6_dns_enabled, true);
  const explicit = runtimeDraft({ ...preferences, ipv6_dns_enabled:true });
  assert.equal(preferencesFromRuntimeDraft(explicit).ipv6_dns_enabled, true);
});

test("IPv6 uses one settings transaction without a dialog and displays On only after success", async () => {
  const state = {toggles:{ipv6DNS:false},engineMutationBusy:false,migrationHandoff:false};
  let snapshot = response();
  snapshot.effective.ipv6_dns_enabled = false;
  snapshot.revision = "current-settings";
  const calls = [];
  let signalWrite;
  const writeStarted = new Promise((resolve) => { signalWrite = resolve; });
  let finishWrite;
  const ui = createRuntimeSettingsUI({state,invoke:async (command, args) => {
    calls.push({command,args});
    if (command === "read_runtime_settings_snapshot") return structuredClone(snapshot);
    assert.equal(command, "write_runtime_settings_snapshot");
    signalWrite();
    await new Promise((resolve) => { finishWrite = resolve; });
    snapshot = { settings:args.settings, revision:"updated-settings", effective:{...snapshot.effective,ipv6_dns_enabled:args.settings.ipv6_dns_enabled} };
    return structuredClone(snapshot);
  },appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){assert.fail("IPv6 does not open a dialog");}});
  const changing = ui.toggleIPv6DNS(true);
  await writeStarted;
  assert.equal(state.toggles.ipv6DNS, false);
  assert.equal(state.engineMutationBusy, true);
  assert.deepEqual(calls[1].args, { settings:{...preferences,ipv6_dns_enabled:true}, revision:"current-settings" });
  finishWrite();
  assert.equal(await changing, true);
  assert.equal(state.toggles.ipv6DNS, true);
  assert.equal(state.engineMutationBusy, false);
  assert.equal(state.runtimeSettingsDialog, undefined);
  assert.equal(calls.length, 2);
});

test("a background settings refresh does not cancel a pending IPv6 choice", async () => {
  const state = {toggles:{ipv6DNS:false},engineMutationBusy:false,migrationHandoff:false};
  const before = response(); before.effective.ipv6_dns_enabled = false;
  let resolveRead;
  const pendingRead = new Promise((resolve) => { resolveRead = resolve; });
  let reads = 0;
  let writes = 0;
  const ui = createRuntimeSettingsUI({state,invoke:async (command, args) => {
    if (command === "read_runtime_settings_snapshot") return ++reads === 1 ? pendingRead : before;
    assert.equal(command, "write_runtime_settings_snapshot");
    writes++;
    return { ...before, settings:args.settings, effective:{...before.effective,ipv6_dns_enabled:true} };
  },appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
  const changing = ui.toggleIPv6DNS(true);
  await ui.load();
  resolveRead(before);
  assert.equal(await changing, true);
  assert.equal(writes, 1);
  assert.equal(state.toggles.ipv6DNS, true);
});

test("IPv6 refuses concurrent mutations and restores observed state after a rejected save", async () => {
  const state = {toggles:{},engineMutationBusy:true,migrationHandoff:false};
  const calls = [];
  const snapshot = response(); snapshot.effective.ipv6_dns_enabled = false;
  const messages = [];
  const ui = createRuntimeSettingsUI({state,invoke:async (command) => {
    calls.push(command);
    if (command === "write_runtime_settings_snapshot") throw new Error("settings changed");
    return snapshot;
  },appendLog(...args){messages.push(args);},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
  await assert.rejects(ui.toggleIPv6DNS(true), /operation is in progress/u);
  assert.deepEqual(calls, []);
  state.engineMutationBusy = false;
  assert.equal(await ui.toggleIPv6DNS(true), false);
  assert.equal(state.toggles.ipv6DNS, false);
  assert.ok(messages.some(([level]) => level === "error"));
});

test("malformed IPv6 DNS observations fail instead of displaying a default", async () => {
  const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
  const bad = response(); bad.effective.ipv6_dns_enabled = "false";
  const ui = createRuntimeSettingsUI({state,invoke:async () => bad,appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
  assert.equal(await ui.load(), false);
  assert.match(state.runtimeSettingsError, /invalid/u);
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
