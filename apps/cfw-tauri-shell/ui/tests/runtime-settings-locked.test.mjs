// The saved network settings while no change of them can be made: a legacy
// cleanup is pending, and the host refuses every write until it completes.
// It says so with the settings. Where they are not in force either, the page
// holds the controls with that reason, in place of the advice to apply them,
// and Reload From Disk offers no form whose Apply would be refused.
import test from "node:test";
import assert from "node:assert/strict";
import { createRuntimeSettingsUI, savedSettingsHeldFor, savedSettingsNotInForce } from "../src/runtime-settings.js";
import { networkSettingsReason } from "../src/reasons.js";

const LOCKED = "settings cannot change until the legacy cleanup completes: the unfinished migration fixed the engine settings until then, so finish the legacy cleanup first";
const RUNNING = Object.freeze({ mixed_port: 7890, log_level: "info", tunnel_mtu: 1500, ipv6_dns_enabled: true, lan_proxy: null,
  mainland_china_direct: false, dns_leak_protection: true, webrtc_leak_protection: false, tcp_concurrency: true });
const SAVED = Object.freeze({ preferred_mixed_port: null, log_level: "info", tunnel_mtu: 1500, allow_lan: false, lan_proxy: null, dns_leak_protection: true });
// The file as something else left it: the protection is gone from it.
const RESTORED = Object.freeze({ preferred_mixed_port: null, log_level: "info", tunnel_mtu: 1500, allow_lan: false, lan_proxy: null });
const snapshot = (settings, revision, inForce, refused) => ({
  tunnel_mtu_limits: { minimum: 1280, maximum: 1500 }, settings: structuredClone(settings), revision,
  effective: structuredClone(RUNNING), in_force: inForce, saved_ipv6_dns_enabled: true, change_refused: refused,
});

/// A page whose host holds `disk`, the answer to a read, and refuses every
/// write with what the disk says no change can be made for, before anything
/// else, as the backend does. It applies nothing.
function page(disk) {
  const state = { activePage: "settings", toggles: {}, engineMutationBusy: false, migrationHandoff: false };
  const host = { disk, writes: [] };
  const logs = [];
  const ui = createRuntimeSettingsUI({
    state,
    invoke: async (command, args) => {
      if (command === "read_runtime_settings_snapshot") return structuredClone(host.disk);
      assert.equal(command, "write_runtime_settings_snapshot");
      host.writes.push(structuredClone(args));
      throw new Error(host.disk.change_refused ?? "this host applies nothing");
    },
    appendLog: (level, _source, message) => { logs.push(`${level}: ${message}`); },
    renderPage() {}, refreshRuntime: () => ui.load(), dismissOtherDialogs() {}, otherDialogOpen: () => false,
  });
  return { state, host, logs, ui };
}

test("held controls give the reason no change can be made for, where there is one", () => {
  assert.equal(savedSettingsHeldFor({ change_refused: LOCKED }), LOCKED);
  for (const free of [{ change_refused: null }, {}]) assert.equal(savedSettingsHeldFor(free), savedSettingsNotInForce());
});

test("the pages hold the controls for it only where the saved settings are not in force", () => {
  const dashboard = (inForce, refused) => ({ runtimeSettings: snapshot(SAVED, "kept", inForce, refused), runtimeSettingsError: null, migrationHandoff: false });
  assert.equal(networkSettingsReason(dashboard(false, LOCKED)), LOCKED);
  assert.equal(networkSettingsReason(dashboard(false, null)), savedSettingsNotInForce());
  // Settings in force keep their controls. The host says why it refuses a
  // change of them, and a reason from an earlier read holds nothing once the
  // cleanup is complete.
  assert.equal(networkSettingsReason(dashboard(true, LOCKED)), null);
  assert.equal(networkSettingsReason(dashboard(true, null)), null);
  // What leaves the network to a migration is said before either.
  assert.equal(networkSettingsReason({ ...dashboard(false, LOCKED), migrationHandoff: true }), "Finish migration before changing network settings");
});

test("on saved settings that are not in force and cannot change, an action says so and writes nothing", async () => {
  const { state, host, logs, ui } = page(snapshot(RESTORED, "restored", false, LOCKED));
  assert.equal(await ui.load(), true);
  assert.equal(state.runtimeSettings.change_refused, LOCKED);
  const actions = [() => ui.toggleMainlandChinaDirect(true), () => ui.toggleDnsLeakProtection(false), () => ui.toggleWebRtcLeakProtection(true),
    () => ui.toggleTcpConcurrency(false), () => ui.toggleIPv6DNS(false), () => ui.toggleLAN(false)];
  for (const action of actions) await assert.rejects(action(), { message: LOCKED });
  // The button of the form opens nothing, and the log says why.
  await ui.open();
  assert.equal(state.runtimeSettingsDialog ?? null, null);
  assert.deepEqual(logs, [`error: ${LOCKED}`]);
  assert.deepEqual(host.writes, []);
});

test("Reload From Disk offers no form whose Apply would be refused, and offers it once the settings can change", async () => {
  const { state, host, logs, ui } = page(snapshot(RESTORED, "restored", false, LOCKED));
  assert.equal(await ui.reload(), false);
  assert.equal(state.runtimeSettingsDialog ?? null, null);
  // The page has what was read, and says the reason beside what it holds.
  assert.deepEqual([state.runtimeSettings.in_force, state.runtimeSettings.change_refused], [false, LOCKED]);
  // Neither does it open while another operation is under way: there is
  // nothing to refuse for that.
  state.engineMutationBusy = true;
  assert.equal(await ui.reload(), false);
  state.engineMutationBusy = false;
  // The cleanup completes.
  host.disk = snapshot(RESTORED, "restored", false, null);
  assert.equal(await ui.reload(), true);
  assert.deepEqual([state.runtimeSettingsDialog.revision, state.runtimeSettingsDialog.basis.in_force], ["restored", false]);
  assert.deepEqual(host.writes, []);
  assert.deepEqual(logs, []);
});

test("settings in force are held for nothing, and their form says why its Apply is refused", async () => {
  const { state, host, logs, ui } = page(snapshot(SAVED, "kept", true, LOCKED));
  assert.equal(await ui.reload(), false, "settings in force are only read");
  await ui.open();
  const dialog = state.runtimeSettingsDialog;
  assert.deepEqual([dialog.revision, dialog.basis.in_force], ["kept", true]);
  assert.equal(await ui.save({ ...SAVED, log_level: "debug" }, dialog.revision, dialog.basis, dialog), false);
  assert.equal(dialog.error, LOCKED);
  assert.equal(state.runtimeSettingsDialog, dialog, "the form stays open");
  assert.equal(host.writes.length, 1);
  assert.deepEqual(logs, [`error: Runtime settings were not applied: ${LOCKED}`]);
});

test("an answer that says in another shape why no change can be made is no settings", async () => {
  for (const value of ["", 0, 1, true, false, {}, [LOCKED]]) {
    const { state, ui } = page(snapshot(SAVED, "kept", true, value));
    assert.equal(await ui.load(), false, JSON.stringify(value));
    assert.equal(state.runtimeSettingsError, "Runtime settings response is invalid", JSON.stringify(value));
    assert.equal(state.runtimeSettings ?? null, null);
  }
  for (const value of [undefined, null, LOCKED]) {
    const { state, ui } = page(snapshot(SAVED, "kept", true, value));
    assert.equal(await ui.load(), true, String(value));
    assert.equal(state.runtimeSettingsError, null);
  }
});
