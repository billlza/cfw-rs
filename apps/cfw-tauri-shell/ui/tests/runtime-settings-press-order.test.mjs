// A press that reads the settings, beside the other reads of the page: Reload
// From Disk and the actions that change settings. What counts is what the
// page knows once the read of the press has ended.
//
// The form of a reload shows the saved settings the page knows then: those it
// read, unless the page has taken newer ones meanwhile, by a read or by a
// change it saved, or holds its controls for a read that it asked for later
// and that failed. Neither does the form open once the user has left the page
// the reload was pressed on, also when the user is back there by then, nor
// when the user had gone to another page as it was pressed.
//
// An action goes on with the settings it read, unless the page holds its
// controls by then, for newer settings that are not in force or for a read it
// asked for later that failed: it would offer or write what the page refuses.
// It gives the reason the page holds them for, whatever its own read found.
//
// A refresh that is only under way takes nothing from either.
import test from "node:test";
import assert from "node:assert/strict";
import { createRuntimeSettingsUI, savedSettingsNotInForce } from "../src/runtime-settings.js";
import { trackPageVisits } from "../src/page-visits.js";

const RUNNING = Object.freeze({ mixed_port: 7890, log_level: "info", tunnel_mtu: 1500, ipv6_dns_enabled: true, lan_proxy: null,
  mainland_china_direct: false, dns_leak_protection: true, webrtc_leak_protection: false, tcp_concurrency: true });
const KEPT = Object.freeze({ preferred_mixed_port: null, log_level: "info", tunnel_mtu: 1500, allow_lan: false, lan_proxy: null, dns_leak_protection: true });
// The file as something else left it, twice: the protection gone, and then a louder log as well.
const RESTORED = Object.freeze({ preferred_mixed_port: null, log_level: "info", tunnel_mtu: 1500, allow_lan: false, lan_proxy: null });
const LOUDER = Object.freeze({ ...RESTORED, log_level: "debug" });
const snapshot = (settings, revision, inForce) => ({
  tunnel_mtu_limits: { minimum: 1280, maximum: 1500 }, settings: structuredClone(settings), revision,
  effective: structuredClone(RUNNING), in_force: inForce, saved_ipv6_dns_enabled: true, change_refused: null,
});
const settle = () => new Promise((resolve) => setImmediate(resolve));
/// What became of `promise` once the answers given so far are worked off: its value, or that it is still under way.
async function outcome(promise) {
  const pending = Symbol("pending");
  const settled = await Promise.race([promise, settle().then(settle).then(() => pending)]);
  return settled === pending ? "under way" : settled;
}

/// A page whose host holds every read of the settings until the test answers it, in any order,
/// and keeps a write at once. `writes` and `logs` are what the page wrote and logged.
function page() {
  const state = trackPageVisits({ toggles: {}, engineMutationBusy: false, migrationHandoff: false }, "settings");
  const reads = [];
  const writes = [];
  const logs = [];
  const ui = createRuntimeSettingsUI({
    state,
    invoke: (command, args) => {
      if (command === "write_runtime_settings_snapshot") {
        writes.push(args);
        return Promise.resolve(snapshot(args.settings, "saved", true));
      }
      assert.equal(command, "read_runtime_settings_snapshot");
      return new Promise((resolve, reject) => { reads.push({ answer: (value) => resolve(structuredClone(value)), refuse: reject }); });
    },
    appendLog: (level, source, message) => { logs.push(message); },
    renderPage() {}, refreshRuntime() {}, dismissOtherDialogs() {}, otherDialogOpen: () => false,
  });
  return { state, reads, writes, logs, ui };
}

test("a reload opens no form once the page has taken newer settings that are in force", async () => {
  const { state, reads, ui } = page();
  const reloaded = ui.reload();
  const refreshed = ui.load();
  await settle();
  reads[1].answer(snapshot(KEPT, "new", true));
  assert.equal(await outcome(refreshed), true);
  reads[0].answer(snapshot(RESTORED, "old", false));
  assert.equal(await outcome(reloaded), false);
  assert.equal(state.runtimeSettingsDialog ?? null, null);
  assert.deepEqual([state.runtimeSettings.revision, state.runtimeSettings.in_force], ["new", true]);
});

test("a reload shows the newer saved settings that the page has taken meanwhile", async () => {
  const { state, reads, ui } = page();
  const reloaded = ui.reload();
  const refreshed = ui.load();
  await settle();
  reads[1].answer(snapshot(LOUDER, "newer", false));
  assert.equal(await outcome(refreshed), true);
  reads[0].answer(snapshot(RESTORED, "old", false));
  assert.equal(await outcome(reloaded), true);
  assert.equal(state.runtimeSettingsDialog.revision, "newer");
  assert.equal(state.runtimeSettingsDialog.basis.in_force, false);
  assert.equal(state.runtimeSettings.revision, "newer", "the page and the form show the same settings");
});

test("a reload opens no form once a change that the page made meanwhile is saved", async () => {
  const { state, reads, ui } = page();
  const reloaded = ui.reload();
  await settle();
  assert.equal(await outcome(ui.save(structuredClone(KEPT), "old", { in_force: true, saved_ipv6_dns_enabled: true })), true);
  reads[0].answer(snapshot(RESTORED, "old", false));
  assert.equal(await outcome(reloaded), false);
  assert.equal(state.runtimeSettingsDialog ?? null, null);
  assert.deepEqual([state.runtimeSettings.revision, state.runtimeSettings.in_force], ["saved", true]);
});

test("a reload shows the newer saved settings that the page took after a later read had failed", async () => {
  const { state, reads, ui } = page();
  const reloaded = ui.reload();
  const failing = ui.load();
  const refreshed = ui.load();
  await settle();
  reads[1].refuse(new Error("settings store is locked"));
  assert.equal(await outcome(failing), false);
  reads[2].answer(snapshot(LOUDER, "newer", false));
  assert.equal(await outcome(refreshed), true);
  reads[0].answer(snapshot(RESTORED, "old", false));
  assert.equal(await outcome(reloaded), true);
  assert.equal(state.runtimeSettingsDialog.revision, "newer");
  assert.equal(state.runtimeSettingsError, null);
});

test("a failure older than the read of a reload keeps no form from opening", async () => {
  const { state, reads, ui } = page();
  const failing = ui.load();
  await settle();
  reads[0].refuse(new Error("settings store is locked"));
  assert.equal(await outcome(failing), false);
  const reloaded = ui.reload();
  const refreshed = ui.load();
  await settle();
  reads[1].answer(snapshot(RESTORED, "old", false));
  assert.equal(await outcome(reloaded), true);
  assert.equal(state.runtimeSettingsDialog.revision, "old");
  reads[2].answer(snapshot(RESTORED, "old", false));
  assert.equal(await outcome(refreshed), true);
  assert.equal(state.runtimeSettingsError, null);
});

test("a refresh that is only under way takes nothing from a reload", async () => {
  const { state, reads, ui } = page();
  const reloaded = ui.reload();
  const refreshed = ui.load();
  await settle();
  reads[0].answer(snapshot(RESTORED, "old", false));
  assert.equal(await outcome(reloaded), true);
  assert.equal(state.runtimeSettingsDialog.revision, "old");
  reads[1].answer(snapshot(RESTORED, "old", false));
  assert.equal(await outcome(refreshed), true);
});

test("a reload opens no form once a read that the page asked for later has failed", async () => {
  const { state, reads, ui } = page();
  const reloaded = ui.reload();
  const refreshed = ui.load();
  await settle();
  reads[1].refuse(new Error("settings store is locked"));
  assert.equal(await outcome(refreshed), false);
  assert.equal(state.runtimeSettingsError, "settings store is locked");
  reads[0].answer(snapshot(RESTORED, "old", false));
  assert.equal(await outcome(reloaded), false);
  assert.equal(state.runtimeSettingsDialog ?? null, null);
  assert.equal(state.runtimeSettingsError, "settings store is locked", "the controls stay held");
});

test("a reload opens no form once the user has left the page it was pressed on, also when back there by then", async () => {
  // Also when the user had gone to another page as it was pressed: the page
  // shown is set as the user goes there, while Settings is still drawn.
  for (const [gone, visited] of [[[], ["connections"]], [[], ["connections", "settings"]], [["connections"], []]]) {
    const name = [...gone, "the press", ...visited].join(", then ");
    const { state, reads, ui } = page();
    for (const visit of gone) state.activePage = visit;
    const reloaded = ui.reload();
    await settle();
    for (const visit of visited) state.activePage = visit;
    reads[0].answer(snapshot(RESTORED, "old", false));
    assert.equal(await outcome(reloaded), false, name);
    assert.equal(state.runtimeSettingsDialog ?? null, null, name);
    assert.deepEqual([state.runtimeSettings.revision, state.runtimeSettings.in_force], ["old", false], "the page takes what it read");
    // On Settings, the next press shows them.
    state.activePage = "settings";
    const again = ui.reload();
    await settle();
    reads[1].answer(snapshot(RESTORED, "old", false));
    assert.equal(await outcome(again), true, name);
    assert.equal(state.runtimeSettingsDialog.revision, "old", name);
  }
});

// The actions that change settings: Configure and the LAN switch turned on
// open the form, the LAN switch turned off and a switch write at once.
const ACTIONS = Object.freeze({
  Configure: (ui) => ui.open(),
  "the LAN switch turned on": (ui) => ui.toggleLAN(true),
  "the LAN switch turned off": (ui) => ui.toggleLAN(false),
  "a switch": (ui) => ui.toggleDnsLeakProtection(false),
});
/// What an action said once it ended: the failure it threw, or else the last
/// line it logged, which is where the form says why it does not open.
const said = (action, logs) => action.then(() => logs.at(-1) ?? null, (error) => error.message);

test("an action changes nothing once the page holds its controls for newer settings that are not in force", async () => {
  // The reason is that of the newer settings: the advice to apply them, or why no change can be made.
  for (const refused of [null, "a legacy cleanup is pending"]) {
    for (const [name, act] of Object.entries(ACTIONS)) {
      const { state, reads, writes, logs, ui } = page();
      const acting = said(act(ui), logs);
      const refreshed = ui.load();
      await settle();
      reads[1].answer({ ...snapshot(RESTORED, "restored", false), change_refused: refused });
      assert.equal(await outcome(refreshed), true, name);
      reads[0].answer(snapshot(KEPT, "kept", true));
      assert.equal(await outcome(acting), refused ?? savedSettingsNotInForce(), name);
      assert.equal(state.runtimeSettingsDialog ?? null, null, name);
      assert.deepEqual(writes, [], name);
    }
  }
});

test("an action changes nothing once a read that the page asked for later has failed", async () => {
  for (const [name, act] of Object.entries(ACTIONS)) {
    const { state, reads, writes, logs, ui } = page();
    const acting = said(act(ui), logs);
    const refreshed = ui.load();
    await settle();
    reads[1].refuse(new Error("settings store is locked"));
    assert.equal(await outcome(refreshed), false, name);
    reads[0].answer(snapshot(KEPT, "kept", true));
    assert.equal(await outcome(acting), "settings store is locked", name);
    assert.equal(state.runtimeSettingsDialog ?? null, null, name);
    assert.deepEqual(writes, [], name);
    assert.equal(state.runtimeSettingsError, "settings store is locked", `${name}: the controls stay held`);
  }
});

test("an action whose own read finds saved settings that are not in force changes nothing, whatever the page took since", async () => {
  // With the reason of its own read: the advice to apply them, or why no change can be made of them.
  for (const refused of [null, "a legacy cleanup is pending"]) {
    for (const [name, act] of Object.entries(ACTIONS)) {
      const { state, reads, writes, logs, ui } = page();
      const acting = said(act(ui), logs);
      const refreshed = ui.load();
      await settle();
      reads[1].answer({ ...snapshot(KEPT, "kept", true), change_refused: refused });
      assert.equal(await outcome(refreshed), true, name);
      reads[0].answer({ ...snapshot(RESTORED, "restored", false), change_refused: refused });
      assert.equal(await outcome(acting), refused ?? savedSettingsNotInForce(), name);
      assert.equal(state.runtimeSettingsDialog ?? null, null, name);
      assert.deepEqual(writes, [], name);
    }
  }
});

test("an action whose own read is not in force gives the reason the page holds its controls for by then", async () => {
  // That of newer settings that no change can be made of, or the failure of a later read: the page gives it beside the controls.
  const later = Object.freeze({
    "a legacy cleanup is pending": (read) => read.answer({ ...snapshot(LOUDER, "louder", false), change_refused: "a legacy cleanup is pending" }),
    "settings store is locked": (read) => read.refuse(new Error("settings store is locked")),
  });
  for (const [reason, end] of Object.entries(later)) {
    for (const [name, act] of Object.entries(ACTIONS)) {
      const { state, reads, writes, logs, ui } = page();
      const acting = said(act(ui), logs);
      const refreshed = ui.load();
      await settle();
      end(reads[1]);
      await outcome(refreshed);
      reads[0].answer(snapshot(RESTORED, "restored", false));
      assert.equal(await outcome(acting), reason, name);
      assert.equal(state.runtimeSettingsDialog ?? null, null, name);
      assert.deepEqual(writes, [], name);
    }
  }
});

test("a refresh that is only under way takes nothing from an action", async () => {
  for (const [name, act] of Object.entries(ACTIONS)) {
    const { state, reads, writes, ui } = page();
    const acting = act(ui);
    const refreshed = ui.load();
    await settle();
    reads[0].answer(snapshot(KEPT, "kept", true));
    await outcome(acting);
    assert.equal(state.runtimeSettingsDialog?.revision ?? writes[0]?.revision, "kept", name);
    reads[1].answer(snapshot(RESTORED, "restored", false));
    await outcome(refreshed);
  }
});
