// The saved network settings beside the ones the engine runs with. A change
// made in the app commits both together. They differ once anything else has
// changed the settings file: the engine keeps what it was given, and a write
// of one more change would apply the rest of the file with it, unasked.
import test from "node:test";
import assert from "node:assert/strict";
import { createRuntimeSettingsUI, savedSettingsNotInForce } from "../src/runtime-settings.js";
import { readFile } from "node:fs/promises";
import { runtimeDialogDescription, runtimeDialogFrame } from "../src/native-runtime-settings.js";
import { outcome } from "./support/outcome.mjs";

const LAN = Object.freeze({ listen: "0.0.0.0", port: 7898, allowed_source_cidrs: Object.freeze(["192.168.1.0/24"]) });
const RUNNING = Object.freeze({ mixed_port: 7890, log_level: "info", tunnel_mtu: 1500, ipv6_dns_enabled: true, lan_proxy: LAN,
  mainland_china_direct: false, dns_leak_protection: true, webrtc_leak_protection: true, tcp_concurrency: true });
const SAVED = Object.freeze({ preferred_mixed_port: null, log_level: "info", tunnel_mtu: 1500, allow_lan: true, lan_proxy: LAN,
  dns_leak_protection: true, webrtc_leak_protection: true });
// The file as something else left it: both protections and LAN sharing are
// gone from it, and the log level is another.
const RESTORED = Object.freeze({ preferred_mixed_port: null, log_level: "warn", tunnel_mtu: 1500, allow_lan: false, lan_proxy: null });
// The switches as the engine runs them, which the form carries: in the
// settings, one that rests is absent.
const KEPT = Object.freeze({ dns_leak_protection: true, webrtc_leak_protection: true });
// The selected profile has IPv6 DNS on, which settings that leave it open
// come to.
const snapshot = (settings, revision, inForce, effective = RUNNING) => ({
  tunnel_mtu_limits: { minimum: 1280, maximum: 1500 }, settings: structuredClone(settings), revision,
  effective: structuredClone(effective), in_force: inForce, saved_ipv6_dns_enabled: settings.ipv6_dns_enabled ?? true,
});
const REASON = "The saved network settings are not the ones in use. Reload From Disk in Settings shows them, and Apply puts them in use.";
const NOTE = "These saved settings are not in use. Apply puts them in use; switches not shown here stay as they are. Connections may reconnect.";
const USUAL = "Changes apply to the current core. Existing connections may reconnect.";
// What the backend refuses a write with that was built on settings in force
// once they are no longer in force.
const REFUSAL = "the saved network settings are not the ones in use";
// What it refuses the Apply of the form on saved settings with once the
// profile gives another IPv6 DNS than that form showed.
const PROFILE_CHANGED = "the selected profile no longer gives the IPv6 DNS setting this form shows";
// What a write says of the snapshot it was built on.
const builtOn = (in_force, saved_ipv6_dns_enabled = true) => ({ in_force, saved_ipv6_dns_enabled });

/// A page whose host holds `disk`, the answer to a read, and applies what is
/// written to it as the backend does: only on the revision it holds, a
/// write built on settings in force only while they are in force, and one
/// built on saved settings that leaves IPv6 DNS to the profile only while
/// the profile gives what the write says the form showed. The profile has
/// IPv6 DNS as `host.profileIPv6DNS` says, on at first.
/// `host.refuse` makes it refuse the next write for another cause, and
/// `host.cannotStart` refuses settings the engine would not start with.
/// `host.otherDialog` says that another dialog of the app is open, and
/// `host.dismissed` counts how often the form closed the others.
function page(disk) {
  const state = { activePage: "settings", toggles: {}, engineMutationBusy: false, migrationHandoff: false };
  const host = { disk, reads: 0, writes: [], refuse: null, cannotStart: () => null, otherDialog: false, dismissed: 0, profileIPv6DNS: true };
  const logs = [];
  const ui = createRuntimeSettingsUI({
    state,
    invoke: async (command, args) => {
      if (command === "read_runtime_settings_snapshot") { host.reads += 1; return structuredClone(host.disk); }
      assert.equal(command, "write_runtime_settings_snapshot");
      host.writes.push(structuredClone(args));
      assert.deepEqual(Object.entries(args.basis).map(([name, value]) => `${name}: ${typeof value}`),
        ["in_force: boolean", "saved_ipv6_dns_enabled: boolean"], "a write says what it was built on");
      if (host.refuse) { const cause = host.refuse; host.refuse = null; throw new Error(cause); }
      if (args.revision !== host.disk.revision) throw new Error("runtime settings changed");
      if (args.basis.in_force && !host.disk.in_force) throw new Error(`${REFUSAL}; Reload From Disk in Settings shows them`);
      if (!args.basis.in_force && args.settings.ipv6_dns_enabled === undefined && args.basis.saved_ipv6_dns_enabled !== host.profileIPv6DNS) {
        throw new Error(`${PROFILE_CHANGED}; cancel it, and Reload From Disk in Settings shows the saved settings as they are now`);
      }
      const cause = host.cannotStart(args.settings);
      if (cause) throw new Error(cause);
      const lan = args.settings.allow_lan ? args.settings.lan_proxy : null;
      host.disk = snapshot(args.settings, "applied", true, { ...RUNNING, log_level: args.settings.log_level, tunnel_mtu: args.settings.tunnel_mtu, lan_proxy: lan,
        ipv6_dns_enabled: args.settings.ipv6_dns_enabled ?? host.profileIPv6DNS,
        mainland_china_direct: args.settings.mainland_china_direct === true, dns_leak_protection: args.settings.dns_leak_protection === true,
        webrtc_leak_protection: args.settings.webrtc_leak_protection === true, tcp_concurrency: args.settings.tcp_concurrency !== false });
      return structuredClone(host.disk);
    },
    appendLog: (level, _source, message) => { logs.push(`${level}: ${message}`); },
    renderPage() {}, refreshRuntime: () => ui.load(),
    dismissOtherDialogs() { host.dismissed += 1; }, otherDialogOpen: () => host.otherDialog,
  });
  return { state, host, logs, ui };
}

/// A page whose host answers a read only when the test says so: `answers[n]`
/// answers the read that was asked n-th, counted from zero. `other` is the
/// other dialogs of the app: whether one is open, and how often the form
/// closed them.
function pageAnsweredByHand() {
  const state = { activePage: "settings", toggles: {}, engineMutationBusy: false, migrationHandoff: false };
  const answers = [];
  const other = { open: false, dismissed: 0 };
  const ui = createRuntimeSettingsUI({
    state,
    invoke: (command) => {
      assert.equal(command, "read_runtime_settings_snapshot");
      return new Promise((resolve) => { answers.push(resolve); });
    },
    appendLog() {}, renderPage() {}, refreshRuntime: () => ui.load(),
    dismissOtherDialogs() { other.dismissed += 1; }, otherDialogOpen: () => other.open,
  });
  return { state, answers, other, ui };
}

/// Presses the Apply of the form that is open.
async function apply(ui) {
  const original = globalThis.document;
  let press;
  globalThis.document = { querySelectorAll: (selector) => (selector === "[data-runtime-save]"
    ? [{ addEventListener: (_event, listener) => { press = listener; } }] : []) };
  try {
    ui.bindDialog();
    await press();
  } finally {
    if (original === undefined) delete globalThis.document;
    else globalThis.document = original;
  }
}

test("the words for settings that are not in force name the way out", () => {
  assert.equal(savedSettingsNotInForce(), REASON);
});

test("an answer that does not say whether the saved settings are in force is no settings", async () => {
  for (const value of [undefined, null, "true", 1]) {
    const answer = snapshot(SAVED, "kept", true);
    if (value === undefined) delete answer.in_force;
    else answer.in_force = value;
    const { state, ui } = page(answer);
    assert.equal(await ui.load(), false, String(value));
    assert.equal(state.runtimeSettings, undefined, String(value));
    assert.match(state.runtimeSettingsError, /Runtime settings response is invalid/u, String(value));
  }
});

test("an answer that does not say what IPv6 DNS the saved settings give is no settings", async () => {
  for (const value of [undefined, null, "true", 1]) {
    const answer = snapshot(SAVED, "kept", true);
    if (value === undefined) delete answer.saved_ipv6_dns_enabled;
    else answer.saved_ipv6_dns_enabled = value;
    const { state, ui } = page(answer);
    assert.equal(await ui.load(), false, String(value));
    assert.equal(state.runtimeSettings, undefined, String(value));
    assert.match(state.runtimeSettingsError, /Runtime settings response is invalid/u, String(value));
  }
});

test("an answer without the engine's LAN listener, or with one that is no listener, is no settings", async () => {
  const listeners = {
    "absent": undefined, "a text": "0.0.0.0:7898", "a flag": true, "a list": [], "an empty record": {},
    "no port": { listen: "0.0.0.0", allowed_source_cidrs: ["192.168.1.0/24"] },
    "a port in text": { ...LAN, port: "7898" },
    "no address": { port: 7898, allowed_source_cidrs: ["192.168.1.0/24"] },
    "an address that is no text": { ...LAN, listen: 0 },
    "no source ranges": { listen: "0.0.0.0", port: 7898 },
    "source ranges that are no list": { ...LAN, allowed_source_cidrs: "192.168.1.0/24" },
    "a source range that is no text": { ...LAN, allowed_source_cidrs: [24] },
  };
  for (const [name, value] of Object.entries(listeners)) {
    const answer = snapshot(SAVED, "kept", true);
    if (value === undefined) delete answer.effective.lan_proxy;
    else answer.effective.lan_proxy = value;
    const { state, ui } = page(answer);
    assert.equal(await ui.load(), false, name);
    assert.equal(state.runtimeSettings, undefined, name);
    assert.equal(state.toggles.allowLan, undefined, name);
    assert.match(state.runtimeSettingsError, /Runtime settings response is invalid/u, name);
  }
});

test("the page shows what the engine runs with, also while other settings are saved", async () => {
  const { state, ui } = page(snapshot(RESTORED, "restored", false));
  assert.equal(await ui.load(), true);
  assert.equal(state.runtimeSettings.in_force, false);
  assert.deepEqual(
    [state.toggles.allowLan, state.toggles.dnsLeakProtection, state.toggles.webrtcLeakProtection, state.toggles.mainlandChinaDirect, state.toggles.tcpConcurrency, state.logLevel],
    [true, true, true, false, true, "info"],
  );
  // And once they are in force again, the same values come from either side.
  const agreed = page(snapshot(SAVED, "kept", true));
  assert.equal(await agreed.ui.load(), true);
  assert.equal(agreed.state.toggles.allowLan, true);
  const off = page(snapshot(RESTORED, "kept", true, { ...RUNNING, lan_proxy: null }));
  assert.equal(await off.ui.load(), true);
  assert.equal(off.state.toggles.allowLan, false);
});

test("no switch is written while the saved settings are not in force", async () => {
  const changes = {
    "Mainland China direct": (ui) => ui.toggleMainlandChinaDirect(true),
    "DNS leak protection": (ui) => ui.toggleDnsLeakProtection(false),
    "WebRTC leak protection": (ui) => ui.toggleWebRtcLeakProtection(false),
    "TCP concurrency": (ui) => ui.toggleTcpConcurrency(false),
    "IPv6 DNS": (ui) => ui.toggleIPv6DNS(false),
    "Allow LAN": (ui) => ui.toggleLAN(false),
  };
  for (const [name, change] of Object.entries(changes)) {
    const { state, host, ui } = page(snapshot(RESTORED, "restored", false));
    await assert.rejects(change(ui), { message: REASON }, name);
    assert.deepEqual(host.writes, [], name);
    // The read of the click is the page's newest, so the page now holds the
    // controls for the same reason.
    assert.equal(state.runtimeSettings.in_force, false, name);
    assert.equal(state.runtimeSettingsDialog, undefined, name);
    assert.equal(state.engineMutationBusy, false, name);
  }
});

test("the buttons of the form and the LAN switch do not open it on settings that are not in force", async () => {
  for (const enableLAN of [false, true]) {
    const { state, host, logs, ui } = page(snapshot(RESTORED, "restored", false));
    await (enableLAN ? ui.toggleLAN(true) : ui.open());
    assert.equal(state.runtimeSettingsDialog, undefined);
    assert.deepEqual(logs, [`error: ${REASON}`]);
    assert.deepEqual(host.writes, []);
  }
});

test("the log level is not written while the saved settings are not in force", async () => {
  const { host, logs, ui } = page(snapshot(RESTORED, "restored", false));
  const original = globalThis.document;
  let choose;
  globalThis.document = { querySelectorAll: (selector) => (selector === "[data-runtime-log-level]"
    ? [{ value: "debug", addEventListener: (_event, listener) => { choose = listener; } }] : []) };
  try {
    ui.bindPage();
    await choose();
  } finally {
    if (original === undefined) delete globalThis.document;
    else globalThis.document = original;
  }
  assert.deepEqual(host.writes, []);
  assert.deepEqual(logs, [`error: ${REASON}`]);
});

test("a click builds on the saved settings while they are in force, and says so", async () => {
  const { state, host, ui } = page(snapshot(SAVED, "kept", true));
  assert.equal(await ui.toggleMainlandChinaDirect(true), true);
  assert.deepEqual(host.writes, [{ settings: { ...SAVED, mainland_china_direct: true }, revision: "kept", basis: builtOn(true) }]);
  assert.equal(state.toggles.mainlandChinaDirect, true);
  assert.equal(state.toggles.dnsLeakProtection, true);
});

test("Reload From Disk shows saved settings that are not in force, and changes nothing by itself", async () => {
  const { state, host, logs, ui } = page(snapshot(RESTORED, "restored", false));
  assert.equal(await ui.reload(), true);
  assert.deepEqual(host.writes, [], "what the engine runs with is changed by the Apply of the form");
  const dialog = state.runtimeSettingsDialog;
  assert.deepEqual([dialog.revision, dialog.basis, dialog.saving, dialog.error], ["restored", builtOn(false), false, null]);
  // The form shows the file, not what the engine runs with.
  assert.deepEqual([dialog.draft.level, dialog.draft.allow, dialog.draft.lanSources], ["warn", false, ""]);
  assert.equal(runtimeDialogDescription(dialog), NOTE);
  assert.ok(ui.renderDialog().includes(`<p class="glass-dialog-copy">${NOTE}</p>`));
  assert.ok(!ui.renderDialog().includes(USUAL));
  // The page keeps showing what the engine runs with, and holds its controls.
  assert.equal(state.runtimeSettings.in_force, false);
  assert.deepEqual([state.toggles.allowLan, state.toggles.dnsLeakProtection, state.logLevel], [true, true, "info"]);
  assert.deepEqual(logs, []);
  // Closing the form leaves all of it as it is.
  ui.close();
  assert.equal(state.runtimeSettingsDialog, null);
  assert.equal(state.runtimeSettings.in_force, false);
  assert.deepEqual(host.writes, []);
});

test("the native form says the same of saved settings that are not in force", async () => {
  const original = globalThis.document;
  globalThis.document = { documentElement: { dataset: { theme: "dark" } } };
  try {
    const restored = page(snapshot(RESTORED, "restored", false));
    await restored.ui.reload();
    assert.equal(runtimeDialogFrame(restored.state.runtimeSettingsDialog).labels.description, NOTE);
    const kept = page(snapshot(SAVED, "kept", true));
    await kept.ui.open();
    assert.deepEqual(kept.state.runtimeSettingsDialog.basis, builtOn(true));
    assert.equal(runtimeDialogFrame(kept.state.runtimeSettingsDialog).labels.description, USUAL);
    assert.ok(kept.ui.renderDialog().includes(`<p class="glass-dialog-copy">${USUAL}</p>`));
  } finally {
    if (original === undefined) delete globalThis.document;
    else globalThis.document = original;
  }
});

test("the Apply of that form puts in use what the form shows, and keeps the switches as the engine runs them", async () => {
  const { state, host, logs, ui } = page(snapshot(RESTORED, "restored", false));
  await ui.reload();
  await apply(ui);
  // The file has neither protection. The form does not show them, and they
  // stay on.
  assert.deepEqual(host.writes, [{ settings: { ...RESTORED, ...KEPT }, revision: "restored", basis: builtOn(false) }]);
  assert.equal(state.runtimeSettingsDialog, null);
  assert.equal(state.runtimeSettings.in_force, true);
  assert.equal(state.runtimeSettings.revision, "applied");
  assert.deepEqual(
    [state.toggles.allowLan, state.toggles.dnsLeakProtection, state.toggles.webrtcLeakProtection, state.logLevel],
    [false, true, true, "warn"],
  );
  assert.equal(state.engineMutationBusy, false);
  assert.deepEqual(logs, ["info: Runtime settings applied and saved"]);
  // After that a switch is written again, on what was applied.
  assert.equal(await ui.toggleMainlandChinaDirect(true), true);
  assert.deepEqual(host.writes[1], { settings: { ...RESTORED, ...KEPT, mainland_china_direct: true }, revision: "applied", basis: builtOn(true) });
});

test("a saved switch that keeps the engine from starting is not in the way of the form", async () => {
  // The file turns on Mainland China direct and turns off TCP concurrency,
  // and the engine cannot start with the first: the rule sets it needs
  // cannot be downloaded. The page holds the switch that would turn it off.
  const { state, host, ui } = page(snapshot({ ...RESTORED, mainland_china_direct: true, tcp_concurrency: false }, "restored", false));
  host.cannotStart = (settings) => (settings.mainland_china_direct ? "the rule sets could not be downloaded" : null);
  await ui.reload();
  const draft = state.runtimeSettingsDialog.draft;
  assert.deepEqual(
    [draft.mainlandChinaDirect, draft.dnsLeakProtection, draft.webrtcLeakProtection, draft.tcpConcurrency],
    [false, true, true, true],
    "the switches as the engine runs them",
  );
  await apply(ui);
  assert.deepEqual(host.writes, [{ settings: { ...RESTORED, ...KEPT }, revision: "restored", basis: builtOn(false) }]);
  assert.equal(state.runtimeSettingsDialog, null);
  assert.equal(state.runtimeSettings.in_force, true);
  assert.deepEqual([state.toggles.mainlandChinaDirect, state.toggles.tcpConcurrency], [false, true]);
});

test("the form shows IPv6 DNS as the saved settings give it, and its Apply puts that in use", async () => {
  // The engine runs with IPv6 DNS turned off by an earlier choice. The file
  // that was put back leaves it to the profile, which has it on.
  const follows = page(snapshot(RESTORED, "restored", false, { ...RUNNING, ipv6_dns_enabled: false }));
  await follows.ui.reload();
  assert.deepEqual([follows.state.runtimeSettingsDialog.draft.ipv6DNS, follows.state.runtimeSettingsDialog.draft.ipv6DNSInherited], [true, true]);
  assert.match(follows.ui.renderDialog(), /data-runtime-field="ipv6DNS" checked/u);
  assert.equal(follows.state.toggles.ipv6DNS, false, "the page shows what the engine runs with");
  await apply(follows.ui);
  assert.equal(Object.hasOwn(follows.host.writes[0].settings, "ipv6_dns_enabled"), false, "the settings still leave it to the profile");
  assert.equal(follows.state.toggles.ipv6DNS, true);
  // The other way round: the file turns it off, and the engine follows the
  // profile.
  const chooses = page(snapshot({ ...RESTORED, ipv6_dns_enabled: false }, "restored", false));
  await chooses.ui.reload();
  assert.deepEqual([chooses.state.runtimeSettingsDialog.draft.ipv6DNS, chooses.state.runtimeSettingsDialog.draft.ipv6DNSInherited], [false, false]);
  assert.doesNotMatch(chooses.ui.renderDialog(), /data-runtime-field="ipv6DNS" checked/u);
  await apply(chooses.ui);
  assert.equal(chooses.host.writes[0].settings.ipv6_dns_enabled, false);
  assert.equal(chooses.state.toggles.ipv6DNS, false);
});

test("the Apply of that form is refused once the profile gives another IPv6 DNS than the form showed", async () => {
  // The engine runs with IPv6 DNS turned off by an earlier choice. The file
  // that was put back leaves it to the profile, which turns it off as well.
  const restored = (profile) => ({ ...snapshot(RESTORED, "restored", false, { ...RUNNING, ipv6_dns_enabled: false }), saved_ipv6_dns_enabled: profile });
  const { state, host, ui } = page(restored(false));
  host.profileIPv6DNS = false;
  await ui.reload();
  const dialog = state.runtimeSettingsDialog;
  assert.deepEqual([dialog.draft.ipv6DNS, dialog.draft.ipv6DNSInherited, dialog.basis], [false, true, builtOn(false, false)]);
  assert.doesNotMatch(ui.renderDialog(), /data-runtime-field="ipv6DNS" checked/u);
  // While the form is open the profile is replaced by one that has IPv6 DNS
  // on, which no revision of the settings says. The untouched Apply would
  // turn it on though the box of the form is not ticked.
  host.profileIPv6DNS = true;
  host.disk = restored(true);
  await apply(ui);
  assert.deepEqual(host.writes, [{ settings: { ...RESTORED, ...KEPT }, revision: "restored", basis: builtOn(false, false) }]);
  assert.match(dialog.error, new RegExp(PROFILE_CHANGED, "u"));
  assert.equal(state.runtimeSettingsDialog, dialog, "the form stays open, and nothing was applied");
  assert.deepEqual([state.toggles.ipv6DNS, state.runtimeSettings.in_force], [false, false]);
  // Opened again, the form shows what the profile gives now, and its Apply
  // puts that in use.
  ui.close();
  assert.equal(await ui.reload(), true);
  assert.match(ui.renderDialog(), /data-runtime-field="ipv6DNS" checked/u);
  await apply(ui);
  assert.deepEqual(host.writes[1], { settings: { ...RESTORED, ...KEPT }, revision: "restored", basis: builtOn(false, true) });
  assert.deepEqual([state.runtimeSettingsDialog, state.toggles.ipv6DNS], [null, true]);
  // A box the user has set is the choice of the form, whatever the profile
  // gives by then.
  const chosen = page(restored(false));
  chosen.host.profileIPv6DNS = false;
  await chosen.ui.reload();
  Object.assign(chosen.state.runtimeSettingsDialog.draft, { ipv6DNS: false, ipv6DNSInherited: false });
  chosen.host.profileIPv6DNS = true;
  await apply(chosen.ui);
  assert.deepEqual(chosen.host.writes, [{ settings: { ...RESTORED, ipv6_dns_enabled: false, ...KEPT }, revision: "restored", basis: builtOn(false, false) }]);
  assert.deepEqual([chosen.state.runtimeSettingsDialog, chosen.state.toggles.ipv6DNS], [null, false]);
});

test("a write names what it was built on as the backend reads it", async () => {
  const source = await readFile(new URL("../../src/commands/runtime_settings.rs", import.meta.url), "utf8");
  const [, struct] = source.match(/#\[serde\(deny_unknown_fields\)\]\npub\(crate\) struct WrittenOn \{\n([^}]*)\}/u);
  const fields = struct.trim().split("\n").map((line) => line.trim());
  assert.deepEqual(fields, ["in_force: bool,", "saved_ipv6_dns_enabled: bool,"]);
  // The command takes it under the name the page gives it, beside the two
  // other arguments of a write.
  const [, taken] = source.match(/pub\(crate\) async fn write_runtime_settings_snapshot\(([^)]*)\)/u);
  assert.match(taken, /,\n\s*settings: RuntimePreferences,\n\s*revision: Option<String>,\n\s*basis: WrittenOn,\n$/u);
  const { host, ui } = page(snapshot(SAVED, "kept", true));
  await ui.toggleMainlandChinaDirect(true);
  assert.deepEqual(Object.keys(host.writes[0]).sort(), ["basis", "revision", "settings"]);
  assert.deepEqual(Object.keys(host.writes[0].basis).map((name) => `${name}: bool,`), fields);
});

test("saved settings that cannot be applied are corrected in that form", async () => {
  // An MTU from another platform, beyond what this one takes.
  const { state, host, ui } = page(snapshot({ ...RESTORED, tunnel_mtu: 9000 }, "legacy", false));
  assert.equal(await ui.reload(), true);
  const dialog = state.runtimeSettingsDialog;
  assert.equal(dialog.draft.mtu, "9000", "the saved value stays visible");
  await apply(ui);
  assert.deepEqual(host.writes, [], "the form refuses the value before anything is written");
  assert.match(dialog.error, /TUN MTU must be 1280–1500/u);
  assert.equal(state.runtimeSettingsDialog, dialog);
  dialog.draft.mtu = "1400";
  await apply(ui);
  assert.deepEqual(host.writes, [{ settings: { ...RESTORED, tunnel_mtu: 1400, ...KEPT }, revision: "legacy", basis: builtOn(false) }]);
  assert.equal(state.runtimeSettingsDialog, null);
  assert.equal(state.runtimeSettings.in_force, true);
  assert.equal(state.runtimeSettings.effective.tunnel_mtu, 1400);
});

test("what the host refuses of the saved settings is said in the form, which stays open for the correction", async () => {
  const lan = { listen: "0.0.0.0", port: 9090, allowed_source_cidrs: ["192.168.1.0/24"] };
  const { state, host, logs, ui } = page(snapshot({ ...RESTORED, allow_lan: true, lan_proxy: lan }, "restored", false));
  await ui.reload();
  const dialog = state.runtimeSettingsDialog;
  host.refuse = "LAN, local proxy and controller ports must be distinct";
  await apply(ui);
  assert.equal(host.writes.length, 1);
  assert.equal(dialog.error, "LAN, local proxy and controller ports must be distinct");
  assert.equal(state.runtimeSettingsDialog, dialog);
  assert.equal(dialog.saving, false);
  assert.equal(state.runtimeSettings.in_force, false, "the page still holds the controls");
  assert.deepEqual(logs, ["error: Runtime settings were not applied: LAN, local proxy and controller ports must be distinct"]);
  dialog.draft.lanPort = "7898";
  await apply(ui);
  assert.deepEqual(host.writes[1], { settings: { ...RESTORED, allow_lan: true, lan_proxy: { ...lan, port: 7898 }, ...KEPT }, revision: "restored", basis: builtOn(false) });
  assert.equal(state.runtimeSettingsDialog, null);
  assert.equal(state.runtimeSettings.in_force, true);
});

test("a form opened on settings in force is refused once they are no longer in force", async () => {
  // There is no file, and the engine runs the defaults: the form opens with
  // no revision. Then DNS leak protection is turned on elsewhere and the file
  // of that change is removed. The revision is the same again.
  const defaults = { preferred_mixed_port: null, log_level: "info", tunnel_mtu: 1500, allow_lan: false, lan_proxy: null };
  const { state, host, ui } = page(snapshot(defaults, null, true, { ...RUNNING, lan_proxy: null, dns_leak_protection: false, webrtc_leak_protection: false }));
  await ui.open();
  const dialog = state.runtimeSettingsDialog;
  assert.deepEqual([dialog.revision, dialog.basis], [null, builtOn(true)]);
  host.disk = snapshot(defaults, null, false, { ...RUNNING, lan_proxy: null, webrtc_leak_protection: false });
  dialog.draft.level = "debug";
  await apply(ui);
  assert.deepEqual(host.writes, [{ settings: { ...defaults, log_level: "debug" }, revision: null, basis: builtOn(true) }]);
  assert.match(dialog.error, new RegExp(REFUSAL, "u"));
  assert.equal(state.runtimeSettingsDialog, dialog);
  // The page read the settings again after the refusal, and holds the controls.
  assert.equal(state.runtimeSettings.in_force, false);
  assert.equal(state.toggles.dnsLeakProtection, true, "the protection stays on");
});

test("Reload From Disk writes nothing and opens nothing while the saved settings are in force", async () => {
  const { state, host, logs, ui } = page(snapshot(SAVED, "kept", true));
  assert.equal(await ui.reload(), false);
  assert.equal(host.reads, 1);
  assert.deepEqual(host.writes, []);
  assert.deepEqual(logs, []);
  assert.equal(state.runtimeSettingsDialog, undefined);
  assert.equal(state.runtimeSettings.revision, "kept");
});

test("Reload From Disk opens nothing while another network operation runs", async () => {
  for (const held of ["engineMutationBusy", "migrationHandoff"]) {
    const { state, host, ui } = page(snapshot(RESTORED, "restored", false));
    state[held] = true;
    await assert.rejects(ui.reload(), { message: "Another network operation is in progress" }, held);
    assert.equal(state.runtimeSettingsDialog, undefined, held);
    assert.deepEqual(host.writes, [], held);
    // The read was made all the same, and the page holds the controls on it.
    assert.equal(state.runtimeSettings.in_force, false, held);
  }
});

test("a read that fails is the failure of Reload From Disk", async () => {
  const { state, ui } = page(null);
  await assert.rejects(ui.reload(), /Runtime settings response is invalid/u);
  assert.match(state.runtimeSettingsError, /Runtime settings response is invalid/u);
  assert.equal(state.runtimeSettingsDialog, undefined);
});

test("of two presses of Reload From Disk the later one opens the form, whichever is answered first", async () => {
  const earlier = snapshot(RESTORED, "earlier", false);
  const later = snapshot({ ...RESTORED, log_level: "debug" }, "later", false);
  // The later press is answered first. The user changes its form, and the
  // answer to the earlier press arrives after that.
  const late = pageAnsweredByHand();
  const [first, second] = [late.ui.reload(), late.ui.reload()];
  late.answers[1](structuredClone(later));
  assert.equal(await outcome(second), true);
  const dialog = late.state.runtimeSettingsDialog;
  assert.deepEqual([dialog.revision, dialog.draft.level], ["later", "debug"]);
  dialog.draft.port = "7895";
  late.answers[0](structuredClone(earlier));
  assert.equal(await outcome(first), false);
  assert.equal(late.state.runtimeSettingsDialog, dialog, "the form the user works in stays");
  assert.deepEqual([dialog.revision, dialog.draft.port], ["later", "7895"]);
  assert.equal(late.state.runtimeSettings.revision, "later");
  // The earlier press is answered first: it opens nothing, the later one does.
  const early = pageAnsweredByHand();
  const [one, two] = [early.ui.reload(), early.ui.reload()];
  early.answers[0](structuredClone(earlier));
  assert.equal(await outcome(one), false);
  assert.equal(early.state.runtimeSettingsDialog, undefined);
  early.answers[1](structuredClone(later));
  assert.equal(await outcome(two), true);
  assert.equal(early.state.runtimeSettingsDialog.revision, "later");
});

test("Reload From Disk opens no form over one that is open", async () => {
  const { state, host, ui } = page(snapshot(RESTORED, "restored", false));
  assert.equal(await ui.reload(), true);
  const dialog = state.runtimeSettingsDialog;
  dialog.draft.port = "7895";
  // The file changes once more, and the reload is pressed again.
  host.disk = snapshot({ ...RESTORED, log_level: "debug" }, "later", false);
  assert.equal(await ui.reload(), false);
  assert.equal(state.runtimeSettingsDialog, dialog);
  assert.deepEqual([dialog.revision, dialog.draft.port, dialog.draft.level], ["restored", "7895", "warn"]);
  // Its Apply is then refused for the revision, and nothing is written over
  // the newer file.
  await apply(ui);
  assert.equal(host.writes.length, 1);
  assert.match(dialog.error, /runtime settings changed/u);
  assert.equal(host.disk.revision, "later");
  // The form is opened by its button while the read of the reload is under
  // way, on settings that are in force by then, and the user works in it
  // when the older answer of the reload arrives.
  const late = pageAnsweredByHand();
  const pressed = late.ui.reload();
  const opened = late.ui.open();
  late.answers[1](snapshot(SAVED, "saved", true));
  assert.equal(await outcome(opened), undefined);
  const shown = late.state.runtimeSettingsDialog;
  shown.draft.level = "error";
  late.answers[0](snapshot(RESTORED, "restored", false));
  assert.equal(await outcome(pressed), false);
  assert.equal(late.state.runtimeSettingsDialog, shown);
  assert.deepEqual([shown.revision, shown.basis.in_force, shown.draft.level], ["saved", true, "error"]);
  assert.equal(late.other.dismissed, 1, "the form closed the other dialogs once, as it opened");
});

test("Reload From Disk opens no form over another dialog, which the form would close", async () => {
  const { state, host, ui } = page(snapshot(RESTORED, "restored", false));
  host.otherDialog = true;
  assert.equal(await ui.reload(), false);
  assert.equal(state.runtimeSettingsDialog, undefined);
  assert.equal(host.dismissed, 0, "the other dialog stays, with what was entered there");
  // The read was made all the same, and the page holds the controls on it.
  assert.equal(state.runtimeSettings.in_force, false);
  // Once that dialog is closed, the next press opens the form.
  host.otherDialog = false;
  assert.equal(await ui.reload(), true);
  assert.equal(host.dismissed, 1);
  // The other dialog is opened while the read of the reload is under way.
  const late = pageAnsweredByHand();
  const pressed = late.ui.reload();
  late.other.open = true;
  late.answers[0](snapshot(RESTORED, "restored", false));
  assert.equal(await outcome(pressed), false);
  assert.equal(late.state.runtimeSettingsDialog, undefined);
  assert.equal(late.other.dismissed, 0);
  assert.equal(late.state.runtimeSettings.in_force, false);
});

test("a saved listener that is kept for later may have the number of the proxy port", async () => {
  // Sharing is off in the file, and its listener has the port the file keeps
  // for the local proxy. The engine opens no listener there, and the backend
  // takes the file as it is.
  const restored = { ...RESTORED, preferred_mixed_port: 7898, lan_proxy: LAN };
  const { state, host, ui } = page(snapshot(restored, "restored", false));
  await ui.reload();
  const dialog = state.runtimeSettingsDialog;
  assert.deepEqual([dialog.draft.port, dialog.draft.lanPort, dialog.draft.allow], ["7898", "7898", false]);
  // Sharing that is turned on in the form needs a port of its own.
  dialog.draft.allow = true;
  await apply(ui);
  assert.deepEqual(host.writes, []);
  assert.equal(dialog.error, "The local and LAN proxy ports must be different");
  dialog.draft.allow = false;
  await apply(ui);
  assert.deepEqual(host.writes, [{ settings: { ...restored, ...KEPT }, revision: "restored", basis: builtOn(false) }]);
  assert.equal(state.runtimeSettingsDialog, null);
  assert.equal(state.runtimeSettings.in_force, true);
});
