import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { acceptNativeRuntimeDraft, createRuntimeSettingsUI, preferencesFromRuntimeDraft, runtimeDraft } from "../src/runtime-settings.js";

const preferences = { preferred_mixed_port:null, log_level:"info", tunnel_mtu:1500, allow_lan:false, lan_proxy:null };
const mtuLimits = { minimum: 1280, maximum: 1500 };
const response = () => ({ tunnel_mtu_limits: { ...mtuLimits }, settings:structuredClone(preferences), revision:null, effective:{mixed_port:7890,log_level:"info",tunnel_mtu:1500,ipv6_dns_enabled:true,lan_proxy:null,mainland_china_direct:false,dns_leak_protection:false,webrtc_leak_protection:false,tcp_concurrency:true} });

test("runtime MTU validation follows the backend bounds and preserves legacy values for editing", () => {
  const draft = runtimeDraft({ ...preferences, tunnel_mtu: 9000 });
  assert.equal(draft.mtu, "9000", "legacy settings are not silently clamped");
  for (const value of ["1279", "1501", "9000"]) {
    draft.mtu = value;
    assert.throws(() => preferencesFromRuntimeDraft(draft, mtuLimits), /1280.*1500/u);
  }
  for (const value of ["1280", "1500"]) {
    draft.mtu = value;
    assert.equal(preferencesFromRuntimeDraft(draft, mtuLimits).tunnel_mtu, Number(value));
  }
  draft.mtu = "9000";
  assert.equal(preferencesFromRuntimeDraft(draft, { minimum: 1280, maximum: 9000 }).tunnel_mtu, 9000);
  for (const limits of [undefined, null, {}, [], {minimum: 1280, maximum: "1500"},
    {minimum: 1500, maximum: 1280}, {minimum: 0, maximum: 1500},
    {minimum: 1280, maximum: 65536}, {minimum: 1280, maximum: 1500, extra: true}]) {
    assert.throws(() => preferencesFromRuntimeDraft(draft, limits), /MTU limits are invalid/u);
  }
});

test("a missing MTU policy blocks opening settings instead of guessing a range", async () => {
  const state = { toggles: {}, engineMutationBusy: false, migrationHandoff: false };
  const snapshot = response();
  delete snapshot.tunnel_mtu_limits;
  const ui = createRuntimeSettingsUI({ state, invoke: async () => snapshot,
    appendLog() {}, renderPage() {}, refreshRuntime() {}, dismissOtherDialogs() { assert.fail("invalid snapshot"); } });
  await ui.open();
  assert.equal(state.runtimeSettingsDialog, undefined);
  assert.match(state.runtimeSettingsError, /MTU limits are invalid/u);
});

test("native MTU correction rejects unsupported values without writing and keeps the original revision", async () => {
  globalThis.document = { documentElement: { dataset: { theme: "dark" } } };
  const state = { toggles: {}, engineMutationBusy: false, migrationHandoff: false };
  const writes = [];
  let handlers, frame;
  let snapshot = { ...response(), settings: { ...preferences, tunnel_mtu: 9000 }, revision: "legacy" };
  const ui = createRuntimeSettingsUI({ state,
    invoke: async (command, args) => {
      if (command === "read_runtime_settings_snapshot") return structuredClone(snapshot);
      assert.equal(command, "write_runtime_settings_snapshot");
      writes.push(args);
      snapshot = { ...response(), settings: args.settings, revision: "corrected" };
      return structuredClone(snapshot);
    },
    nativeDialog: { enabled: () => true, sync: (_dialog, value, callbacks) => { frame = value; handlers = callbacks; return null; } },
    appendLog() {}, renderPage() {}, refreshRuntime() {}, dismissOtherDialogs() {},
  });
  await ui.open();
  const dialog = state.runtimeSettingsDialog;
  ui.renderDialog();
  assert.equal(frame.labels.mtu, "TUN MTU (1280–1500)");
  assert.equal(frame.draft.mtu, "9000");
  await handlers.onSubmit(nativeDraft(dialog.draft));
  assert.equal(writes.length, 0);
  assert.match(dialog.error, /1280.*1500/u);
  await handlers.onSubmit(nativeDraft(dialog.draft, { mtu: "1500" }));
  assert.equal(writes.length, 1);
  assert.equal(writes[0].revision, "legacy");
  assert.equal(writes[0].settings.tunnel_mtu, 1500);
  assert.equal(state.runtimeSettingsDialog, null);
});

// The native form receives exactly the fields runtimeDialogFrame sends.
function nativeDraft(draft, edits = {}) {
  const { initialIPv6DNS, ipv6DNSInherited, mainlandChinaDirect, dnsLeakProtection, webrtcLeakProtection, tcpConcurrency, ...fields } = draft;
  return { ...fields, ipv6DNSEdited: !ipv6DNSInherited, ...edits };
}

test("native form retains inherited IPv6 unless explicitly touched and rejects expanded drafts", () => {
  const prior = runtimeDraft(preferences, { ipv6_dns_enabled: false });
  const retained = acceptNativeRuntimeDraft(prior, nativeDraft(prior, { level: "debug" }));
  assert.equal(Object.hasOwn(preferencesFromRuntimeDraft(retained, mtuLimits), "ipv6_dns_enabled"), false);
  const touched = acceptNativeRuntimeDraft(prior, nativeDraft(prior, { ipv6DNSEdited: true }));
  assert.equal(preferencesFromRuntimeDraft(touched, mtuLimits).ipv6_dns_enabled, false, "choosing then reverting is still explicit");
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
  assert.deepEqual(preferencesFromRuntimeDraft(draft, mtuLimits), preferences);
  draft.allow = true;
  assert.throws(() => preferencesFromRuntimeDraft(draft, mtuLimits), /trusted LAN source ranges/u);
  draft.lanSources = "192.168.1.0/24";
  assert.equal(preferencesFromRuntimeDraft(draft, mtuLimits).lan_proxy.listen, "0.0.0.0");
  draft.port = "80";
  assert.throws(() => preferencesFromRuntimeDraft(draft, mtuLimits), /Proxy port/u);
  draft.port = "7898";
  assert.throws(() => preferencesFromRuntimeDraft(draft, mtuLimits), /must be different/u);
  draft.port = "8890"; draft.mtu = "99999";
  assert.throws(() => preferencesFromRuntimeDraft(draft, mtuLimits), /MTU/u);
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
  assert.equal(preferencesFromRuntimeDraft(draft, mtuLimits).ipv6_dns_enabled, false);
  assert.equal(runtimeDraft({ ...preferences, ipv6_dns_enabled:false }).ipv6DNS, false);
  draft.ipv6DNS = "false";
  assert.throws(() => preferencesFromRuntimeDraft(draft, mtuLimits), /IPv6 DNS/u);
});

test("unrelated settings preserve inherited DNS while an explicit IPv6 choice is retained", () => {
  const draft = runtimeDraft(preferences, { ipv6_dns_enabled:false });
  assert.equal(draft.ipv6DNS, false, "the editor displays the imported policy actually in use");
  draft.level = "debug";
  assert.equal(Object.hasOwn(preferencesFromRuntimeDraft(draft, mtuLimits), "ipv6_dns_enabled"), false);
  draft.ipv6DNS = true;
  assert.equal(preferencesFromRuntimeDraft(draft, mtuLimits).ipv6_dns_enabled, true);
  const explicit = runtimeDraft({ ...preferences, ipv6_dns_enabled:true });
  assert.equal(preferencesFromRuntimeDraft(explicit, mtuLimits).ipv6_dns_enabled, true);
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
    snapshot = { ...snapshot, settings:args.settings, revision:"updated-settings", effective:{...snapshot.effective,ipv6_dns_enabled:args.settings.ipv6_dns_enabled} };
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

// The dialog, the Allow LAN switch and the log level select read the settings
// for their own action too. In each test the action's read is still on its
// way when a background refresh starts and ends.
test("a background settings refresh does not keep the network settings from opening", async () => {
  const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
  let resolveRead;
  const pendingRead = new Promise((resolve) => { resolveRead = resolve; });
  let reads = 0;
  const ui = createRuntimeSettingsUI({state,invoke:async (command) => {
    assert.equal(command, "read_runtime_settings_snapshot");
    return ++reads === 1 ? pendingRead : response();
  },appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
  const opening = ui.open();
  assert.equal(await ui.load(), true);
  resolveRead({ ...response(), revision: "read-for-the-dialog" });
  await opening;
  assert.equal(state.runtimeSettingsDialog?.revision, "read-for-the-dialog");
  assert.equal(state.runtimeSettings.revision, null, "the page shows the refresh, which it asked for after the dialog's read");
  assert.equal(state.runtimeSettingsError, null);
});

test("a background settings refresh does not cancel turning LAN sharing off", async () => {
  const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
  const lan = { listen: "0.0.0.0", port: 7898, allowed_source_cidrs: ["192.168.1.0/24"] };
  const shared = { ...response(), settings: { ...preferences, allow_lan: true, lan_proxy: lan }, revision: "shared" };
  let resolveRead;
  const pendingRead = new Promise((resolve) => { resolveRead = resolve; });
  let reads = 0;
  const writes = [];
  const ui = createRuntimeSettingsUI({state,invoke:async (command, args) => {
    if (command === "read_runtime_settings_snapshot") return ++reads === 1 ? pendingRead : structuredClone(shared);
    assert.equal(command, "write_runtime_settings_snapshot");
    writes.push(args);
    return { ...shared, settings: args.settings, revision: "unshared" };
  },appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){assert.fail("turning sharing off opens no dialog");}});
  const changing = ui.toggleLAN(false);
  assert.equal(await ui.load(), true);
  resolveRead(structuredClone(shared));
  assert.equal(await changing, true);
  assert.deepEqual(writes, [{ settings: { ...preferences, allow_lan: false, lan_proxy: lan }, revision: "shared" }]);
  assert.equal(state.toggles.allowLan, false);
});

test("a background settings refresh does not cancel a chosen log level", async () => {
  const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
  let resolveRead;
  const pendingRead = new Promise((resolve) => { resolveRead = resolve; });
  let reads = 0;
  const writes = [];
  const messages = [];
  const ui = createRuntimeSettingsUI({state,invoke:async (command, args) => {
    if (command === "read_runtime_settings_snapshot") return ++reads === 1 ? pendingRead : response();
    assert.equal(command, "write_runtime_settings_snapshot");
    writes.push(args);
    return { ...response(), settings: args.settings, revision: "levelled", effective: { ...response().effective, log_level: args.settings.log_level } };
  },appendLog(...args){messages.push(args);},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
  const originalDocument = globalThis.document;
  let choose;
  globalThis.document = { querySelectorAll: (selector) => (selector === "[data-runtime-log-level]"
    ? [{ value: "debug", addEventListener: (_event, listener) => { choose = listener; } }] : []) };
  try {
    ui.bindPage();
    const changing = choose();
    assert.equal(await ui.load(), true);
    resolveRead(response());
    await changing;
  } finally {
    if (originalDocument === undefined) delete globalThis.document;
    else globalThis.document = originalDocument;
  }
  assert.deepEqual(writes, [{ settings: { ...preferences, log_level: "debug" }, revision: null }]);
  assert.equal(state.logLevel, "debug");
  assert.deepEqual(messages.filter(([level]) => level === "error"), []);
});

test("a read that was already on its way cannot take the settings back from an action", async () => {
  const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
  let rejectRead;
  const pendingRead = new Promise((_resolve, reject) => { rejectRead = reject; });
  let reads = 0;
  const ui = createRuntimeSettingsUI({state,invoke:async () => (++reads === 1 ? pendingRead : response()),
    appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
  const refreshing = ui.load();
  await ui.open();
  rejectRead(new Error("settings store is locked"));
  assert.equal(await refreshing, false);
  assert.equal(state.runtimeSettingsError, null, "the dialog's own read succeeded after that one began");
  assert.equal(state.runtimeSettingsDialog.revision, null);
});

test("an action on the network settings reports a read that failed and changes nothing", async () => {
  const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
  const calls = [];
  const logged = [];
  const ui = createRuntimeSettingsUI({state,invoke:async (command) => {
    calls.push(command);
    throw new Error("settings store is locked");
  },appendLog(...entry){logged.push(entry);},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){assert.fail("no dialog without settings");}});
  await ui.open();
  assert.equal(state.runtimeSettingsDialog, undefined);
  assert.equal(state.runtimeSettingsError, "settings store is locked");
  assert.deepEqual(logged, [["error", "settings", "settings store is locked"]], "the click that opens the dialog says so in the log");
  state.runtimeSettingsError = null;
  await assert.rejects(ui.toggleLAN(false), /settings store is locked/u);
  assert.equal(state.runtimeSettingsError, "settings store is locked");
  assert.deepEqual(calls, ["read_runtime_settings_snapshot", "read_runtime_settings_snapshot"]);
  // A stored switch reads the settings for its own action as well, and tells
  // the page about a read that failed in the same way.
  for (const [method, enabled] of [["toggleIPv6DNS", false], ...SWITCHES.map((sw) => [sw.method, !sw.resting])]) {
    state.runtimeSettingsError = null;
    calls.length = 0;
    await assert.rejects(ui[method](enabled), /settings store is locked/u, method);
    assert.equal(state.runtimeSettingsError, "settings store is locked", method);
    assert.deepEqual(calls, ["read_runtime_settings_snapshot"], method);
  }
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
  assert.equal(await ui.save(preferencesFromRuntimeDraft(dialog.draft, mtuLimits), "old-revision", dialog), false);
  assert.equal(submitted.revision, "old-revision");
  assert.equal(state.runtimeSettings.settings.log_level, "info");
  assert.equal(dialog.draft.level, "debug", "a failed save preserves the editable draft");
  assert.equal(dialog.error, "settings changed");
  assert.equal(refreshed, 1);
  assert.equal(state.engineMutationBusy, false);
  assert.ok(messages.some(([level]) => level === "error"));
});

// The runtime switches share one transaction path; each is checked on
// its own stored key, state field and toggle method. A switch rests at the
// value its stored key stands for while absent.
const SWITCHES = [
  { key: "mainland_china_direct", toggle: "mainlandChinaDirect", method: "toggleMainlandChinaDirect", label: "mainland China direct", resting: false },
  { key: "dns_leak_protection", toggle: "dnsLeakProtection", method: "toggleDnsLeakProtection", label: "DNS leak protection", resting: false },
  { key: "webrtc_leak_protection", toggle: "webrtcLeakProtection", method: "toggleWebRtcLeakProtection", label: "WebRTC leak protection", resting: false },
  { key: "tcp_concurrency", toggle: "tcpConcurrency", method: "toggleTcpConcurrency", label: "TCP concurrency", resting: true },
];

for (const sw of SWITCHES) {
  test(`${sw.label} observations are strictly typed and an absent stored key means ${sw.resting ? "on" : "off"}`, async () => {
    const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
    let snapshot;
    const ui = createRuntimeSettingsUI({state,invoke:async () => snapshot,appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
    snapshot = response();
    assert.equal(await ui.load(), true, "control: the stored key is absent at rest");
    assert.equal(state.toggles[sw.toggle], sw.resting);
    assert.equal(runtimeDraft(snapshot.settings)[sw.toggle], sw.resting, "the draft reads the absent key the same way");
    for (const stored of [true, false]) {
      snapshot = response();
      snapshot.settings[sw.key] = stored;
      snapshot.effective[sw.key] = stored;
      assert.equal(await ui.load(), true, String(stored));
      assert.equal(state.toggles[sw.toggle], stored);
    }
    for (const [where, value] of [["effective", undefined], ["effective", "true"], ["effective", 1], ["effective", null], ["settings", "true"], ["settings", 1], ["settings", null]]) {
      snapshot = response();
      if (value === undefined) delete snapshot[where][sw.key];
      else snapshot[where][sw.key] = value;
      state.runtimeSettingsError = null;
      assert.equal(await ui.load(), false, `${where}=${String(value)}`);
      assert.match(state.runtimeSettingsError, /invalid/u);
    }
  });

  test(`${sw.label} uses one settings transaction and shows the change only after success`, async () => {
    const state = {toggles:{[sw.toggle]:sw.resting},engineMutationBusy:false,migrationHandoff:false};
    let snapshot = response();
    snapshot.revision = "current-settings";
    const calls = [];
    let signalWrite, finishWrite;
    const writeStarted = new Promise((resolve) => { signalWrite = resolve; });
    const ui = createRuntimeSettingsUI({state,invoke:async (command, args) => {
      calls.push({command,args});
      if (command === "read_runtime_settings_snapshot") return structuredClone(snapshot);
      assert.equal(command, "write_runtime_settings_snapshot");
      signalWrite();
      await new Promise((resolve) => { finishWrite = resolve; });
      snapshot = { ...snapshot, settings:args.settings, revision:"updated-settings", effective:{...snapshot.effective,[sw.key]:args.settings[sw.key]} };
      return structuredClone(snapshot);
    },appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){assert.fail("the switch opens no dialog");}});
    const changing = ui[sw.method](!sw.resting);
    await writeStarted;
    assert.equal(state.toggles[sw.toggle], sw.resting);
    assert.equal(state.engineMutationBusy, true);
    assert.deepEqual(calls[1].args, { settings:{...preferences,[sw.key]:!sw.resting}, revision:"current-settings" });
    finishWrite();
    assert.equal(await changing, true);
    assert.equal(state.toggles[sw.toggle], !sw.resting);
    assert.equal(state.engineMutationBusy, false);
    assert.equal(calls.length, 2);
    const turningBack = ui[sw.method](sw.resting);
    await new Promise((resolve) => setImmediate(resolve));
    finishWrite();
    assert.equal(await turningBack, true);
    assert.equal(calls.at(-1).args.settings[sw.key], sw.resting);
    assert.equal(state.toggles[sw.toggle], sw.resting);
  });

  test(`${sw.label} refuses concurrent mutations, non-boolean input and keeps the observed state after a rejected save`, async () => {
    const state = {toggles:{[sw.toggle]:sw.resting},engineMutationBusy:true,migrationHandoff:false};
    const calls = [];
    const messages = [];
    const ui = createRuntimeSettingsUI({state,invoke:async (command) => {
      calls.push(command);
      if (command === "write_runtime_settings_snapshot") throw new Error("initialize rule-set: download failed; the previous runtime was restored");
      return response();
    },appendLog(...args){messages.push(args);},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
    await assert.rejects(ui[sw.method](!sw.resting), /operation is in progress/u);
    state.engineMutationBusy = false;
    state.migrationHandoff = true;
    await assert.rejects(ui[sw.method](!sw.resting), /operation is in progress/u);
    state.migrationHandoff = false;
    await assert.rejects(ui[sw.method]("true"), TypeError);
    assert.deepEqual(calls, []);
    assert.equal(await ui[sw.method](!sw.resting), false);
    assert.equal(state.toggles[sw.toggle], sw.resting);
    assert.ok(messages.some(([level, , text]) => level === "error" && /rule-set/u.test(text)));
  });

  test(`saving any other setting never takes ${sw.label} back to rest`, async () => {
    globalThis.document = { documentElement: { dataset: { theme: "light" } } };
    for (const path of ["web dialog", "native dialog", "LAN off"]) {
      const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
      const changed = () => {
        const snapshot = response();
        snapshot.revision = "changed";
        snapshot.settings[sw.key] = !sw.resting;
        snapshot.effective[sw.key] = !sw.resting;
        return snapshot;
      };
      const writes = [];
      let callbacks;
      const ui = createRuntimeSettingsUI({state,
        invoke:async (command, args) => {
          if (command === "read_runtime_settings_snapshot") return changed();
          writes.push(args);
          return { ...changed(), settings:args.settings };
        },
        nativeDialog: path === "native dialog" ? { enabled: () => true, sync: (dialog, frame, handlers) => { callbacks = handlers; return null; } } : undefined,
        appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
      if (path === "LAN off") {
        assert.equal(await ui.toggleLAN(false), true);
      } else {
        await ui.open();
        const dialog = state.runtimeSettingsDialog;
        if (path === "web dialog") {
          dialog.draft.level = "debug";
          assert.equal(await ui.save(preferencesFromRuntimeDraft(dialog.draft, mtuLimits), dialog.revision, dialog), true);
        } else {
          ui.renderDialog();
          await callbacks.onSubmit(nativeDraft(dialog.draft, { level: "debug" }));
        }
      }
      assert.equal(writes.length, 1, path);
      assert.equal(writes[0].settings[sw.key], !sw.resting, path);
    }
  });
}

test("the native settings draft stays closed to the runtime switches", async () => {
  const { runtimeDialogFrame } = await import("../src/native-runtime-settings.js");
  globalThis.document = { documentElement: { dataset: { theme: "light" } } };
  const draft = runtimeDraft({ ...preferences, mainland_china_direct: true, dns_leak_protection: true, webrtc_leak_protection: true, tcp_concurrency: false });
  assert.equal(draft.mainlandChinaDirect, true);
  assert.equal(draft.dnsLeakProtection, true);
  assert.equal(draft.webrtcLeakProtection, true);
  assert.equal(draft.tcpConcurrency, false);
  assert.deepEqual(Object.keys(runtimeDialogFrame({ draft, mtuLimits, saving:false, error:null }).draft).sort(),
    ["allow", "ipv6DNS", "ipv6DNSEdited", "lanAddress", "lanPort", "lanSources", "level", "mtu", "port"]);
  for (const extra of [{ mainlandChinaDirect: false }, { dnsLeakProtection: false }, { webrtcLeakProtection: false }, { tcpConcurrency: true }]) {
    assert.throws(() => acceptNativeRuntimeDraft(draft, { ...nativeDraft(draft), ...extra }), /draft is invalid/u);
  }
  const kept = preferencesFromRuntimeDraft(acceptNativeRuntimeDraft(draft, nativeDraft(draft)), mtuLimits);
  assert.equal(kept.mainland_china_direct, true);
  assert.equal(kept.dns_leak_protection, true);
  assert.equal(kept.webrtc_leak_protection, true);
  assert.equal(kept.tcp_concurrency, false);
  const resting = runtimeDraft(preferences);
  for (const key of ["mainland_china_direct", "dns_leak_protection", "webrtc_leak_protection", "tcp_concurrency"]) {
    assert.equal(Object.hasOwn(preferencesFromRuntimeDraft(resting, mtuLimits), key), false, `${key}: a switch at rest keeps the legacy shape`);
  }
  for (const field of ["mainlandChinaDirect", "dnsLeakProtection", "webrtcLeakProtection", "tcpConcurrency"]) {
    const invalid = runtimeDraft(preferences);
    invalid[field] = "true";
    assert.throws(() => preferencesFromRuntimeDraft(invalid, mtuLimits), TypeError, field);
  }
});

test("the component integration harness serves runtime snapshots the renderer accepts", async () => {
  const integration = new URL("../../../../native/dashboard/Integration/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", integration), "utf8")).read_runtime_settings_snapshot;
  const state = {toggles:{},engineMutationBusy:false,migrationHandoff:false};
  const ui = createRuntimeSettingsUI({state,invoke:async () => structuredClone(fixture),appendLog(){},renderPage(){},refreshRuntime(){},dismissOtherDialogs(){}});
  assert.equal(await ui.load(), true, state.runtimeSettingsError);
  assert.equal(state.toggles.mainlandChinaDirect, false);
  assert.equal(state.toggles.dnsLeakProtection, false);
  assert.equal(state.toggles.webrtcLeakProtection, false);
  assert.equal(state.toggles.tcpConcurrency, true);
  // Its write handler rebuilds the effective view, which must keep every field.
  const host = await readFile(new URL("Main.swift", integration), "utf8");
  const rebuilt = host.match(/case "write_runtime_settings_snapshot":[\s\S]*?snapshot\["effective"\] = \[([\s\S]*?)\n\s*\]/u)?.[1];
  assert.ok(rebuilt, "the harness write handler rebuilds the effective view");
  assert.deepEqual([...rebuilt.matchAll(/"([a-z0-9_]+)":/gu)].map((match) => match[1]).sort(), Object.keys(fixture.effective).sort());
  // Both match the fields the Rust command returns.
  const command = await readFile(new URL("../../src/commands/runtime_settings.rs", import.meta.url), "utf8");
  const declared = command.match(/pub\(crate\) struct RuntimeSettingsEffective \{([\s\S]*?)\n\}/u)?.[1];
  assert.ok(declared, "the Rust command declares the effective view");
  assert.deepEqual([...declared.matchAll(/^\s+([a-z0-9_]+):/gmu)].map((match) => match[1]).sort(), Object.keys(fixture.effective).sort());
});
