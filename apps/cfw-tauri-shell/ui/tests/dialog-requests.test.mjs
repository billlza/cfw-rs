// The dialogs that read before they open: the network settings form, and the
// one for shortcuts and network rules. Each closes the other as it opens. An
// answer that arrives late would therefore take the place of a dialog the
// user has asked for since, or works in already. Only the dialog that was
// asked for last opens.
import test from "node:test";
import assert from "node:assert/strict";
import { createRuntimeSettingsUI, savedSettingsNotInForce } from "../src/runtime-settings.js";
import { createAutomationSettingsUI } from "../src/automation-settings.js";
import { askForDialog, openOverlays, watchDialogRequests } from "../src/dialog-requests.js";
import { trackPageVisits } from "../src/page-visits.js";
import { outcome } from "./support/outcome.mjs";

const RUNNING = Object.freeze({ mixed_port: 7890, log_level: "info", tunnel_mtu: 1500, ipv6_dns_enabled: true, lan_proxy: null,
  mainland_china_direct: false, dns_leak_protection: false, webrtc_leak_protection: false, tcp_concurrency: true });
const SAVED = Object.freeze({ preferred_mixed_port: null, log_level: "info", tunnel_mtu: 1500, allow_lan: false, lan_proxy: null });
const settings = (revision, inForce, level = "info") => ({
  tunnel_mtu_limits: { minimum: 1280, maximum: 1500 }, settings: { ...SAVED, log_level: level }, revision,
  effective: { ...RUNNING }, in_force: inForce, saved_ipv6_dns_enabled: true,
});
const rules = (revision) => ({ settings: { shortcuts: [], network_enabled: false, network_rules: [] }, revision, network: null });

/// The two dialogs on Settings, wired as the app wires them: each closes the
/// other as it opens, and `dismiss` closes every overlay as Escape and the
/// backdrop do, both forms among them. The host answers a read only when the
/// test says so: `asked[n]` is the read that was asked n-th, counted from zero.
function app() {
  const state = trackPageVisits({ toggles: {}, engineMutationBusy: false, migrationHandoff: false }, "settings");
  const asked = [];
  const logs = [];
  const page = { renders: 0 };
  const shared = {
    state,
    invoke: (command) => new Promise((answer, refuse) => { asked.push({ command, answer, refuse }); }),
    appendLog: (level, _source, message) => { logs.push(`${level}: ${message}`); },
    renderPage() { page.renders += 1; },
  };
  const automation = createAutomationSettingsUI({ ...shared, dismissOtherDialogs: () => { network.close(); state.glassDialog = null; } });
  const network = createRuntimeSettingsUI({ ...shared, refreshRuntime: () => network.load(),
    dismissOtherDialogs: () => { automation.close(); state.glassDialog = null; },
    otherDialogOpen: () => Boolean(state.automationDialog || state.glassDialog) });
  const dismiss = () => { network.close(); automation.close(); state.profileContextMenu = null; state.glassDialog = null; };
  return { state, asked, logs, page, automation, network, dismiss };
}

test("the order of the requests says which one was made last", () => {
  const state = {};
  const untouched = watchDialogRequests(state);
  assert.equal(untouched(), true);
  assert.equal(Object.hasOwn(state, "dialogRequests"), false, "watching asks for nothing");
  const first = askForDialog(state);
  assert.deepEqual([first(), untouched()], [true, false]);
  const since = watchDialogRequests(state);
  assert.deepEqual([first(), since()], [true, true]);
  const second = askForDialog(state);
  assert.deepEqual([first(), second(), since()], [false, true, false]);
  // Each page has an order of its own.
  const other = {};
  const there = askForDialog(other);
  assert.deepEqual([there(), second()], [true, true]);
});

test("a request may open only while no overlay that opened since is open", () => {
  for (const overlay of ["profileContextMenu", "glassDialog", "runtimeSettingsDialog", "automationDialog"]) {
    const state = {};
    const asked = askForDialog(state);
    state[overlay] = { kind: "opened since" };
    assert.equal(asked(), false, overlay);
    state[overlay] = null;
    assert.equal(asked(), true, `${overlay} closed again`);
    // One that was open at the request takes nothing from it, while it stays the one that is open.
    state[overlay] = { kind: "open at the request" };
    const over = askForDialog(state);
    assert.equal(over(), true, overlay);
    state[overlay] = { kind: "another" };
    assert.equal(over(), false, `${overlay} replaced`);
  }
  assert.deepEqual(openOverlays({ glassDialog: null, automationDialog: undefined }), []);
});

test("the form asked for by its button does not replace the form a reload has opened since", async () => {
  const { state, asked, network } = app();
  // The button is pressed while the saved settings are in force. Before its
  // read ends, the file is found changed by a reload, whose read ends first.
  const configured = network.open();
  const reloaded = network.reload();
  asked[1].answer(settings("restored", false, "warn"));
  assert.equal(await outcome(reloaded), true);
  const form = state.runtimeSettingsDialog;
  assert.deepEqual([form.revision, form.basis.in_force], ["restored", false]);
  form.draft.port = "7895";
  asked[0].answer(settings("kept", true));
  assert.equal(await outcome(configured), undefined);
  assert.equal(state.runtimeSettingsDialog, form, "the form the user works in stays");
  assert.deepEqual([form.revision, form.basis.in_force, form.draft.port, form.draft.level], ["restored", false, "7895", "warn"]);
});

test("of two presses of the form's button only the last opens the form", async () => {
  // Answered in the order they were asked.
  const ordered = app();
  const [one, two] = [ordered.network.open(), ordered.network.open()];
  ordered.asked[0].answer(settings("one", true));
  assert.equal(await outcome(one), undefined);
  assert.equal(ordered.state.runtimeSettingsDialog, undefined);
  ordered.asked[1].answer(settings("two", true));
  assert.equal(await outcome(two), undefined);
  assert.equal(ordered.state.runtimeSettingsDialog.revision, "two");
  // Answered the other way round: the older answer takes nothing from the
  // form the user works in by then.
  const reversed = app();
  const [early, late] = [reversed.network.open(), reversed.network.open()];
  reversed.asked[1].answer(settings("two", true));
  assert.equal(await outcome(late), undefined);
  const form = reversed.state.runtimeSettingsDialog;
  form.draft.level = "debug";
  reversed.asked[0].answer(settings("one", true));
  assert.equal(await outcome(early), undefined);
  assert.equal(reversed.state.runtimeSettingsDialog, form);
  assert.deepEqual([form.revision, form.draft.level], ["two", "debug"]);
});

test("a reload opens no form once another dialog was asked for, and takes nothing from that one", async () => {
  const { state, asked, automation, network } = app();
  const reloaded = network.reload();
  const wanted = automation.open();
  // The read of the reload ends first, and finds saved settings to show.
  asked[0].answer(settings("restored", false));
  assert.equal(await outcome(reloaded), false);
  assert.equal(state.runtimeSettingsDialog, undefined);
  assert.equal(state.runtimeSettings.in_force, false, "the page holds the controls on what was read");
  asked[1].answer(rules("kept"));
  assert.equal(await outcome(wanted), undefined);
  assert.equal(state.automationDialog?.snapshot.revision, "kept", "the dialog that was asked for last opens");
  assert.equal(state.runtimeSettingsDialog ?? null, null);
  // The same with the form's own button pressed after the reload.
  const pressed = app();
  const [again, configured] = [pressed.network.reload(), pressed.network.open()];
  pressed.asked[0].answer(settings("restored", false));
  assert.equal(await outcome(again), false);
  assert.equal(pressed.state.runtimeSettingsDialog, undefined);
  pressed.asked[1].answer(settings("kept", true));
  assert.equal(await outcome(configured), undefined);
  assert.equal(pressed.state.runtimeSettingsDialog.revision, "kept");
});

test("a reload that finds nothing to show takes the place of no dialog that is under way", async () => {
  const { state, asked, automation, network } = app();
  const wanted = automation.open();
  const reloaded = network.reload();
  asked[1].answer(settings("kept", true));
  assert.equal(await outcome(reloaded), false);
  asked[0].answer(rules("kept"));
  assert.equal(await outcome(wanted), undefined);
  assert.equal(state.automationDialog?.snapshot.revision, "kept");
  // Neither of the form its button asked for.
  const pressed = app();
  const [configured, again] = [pressed.network.open(), pressed.network.reload()];
  pressed.asked[1].answer(settings("kept", true));
  assert.equal(await outcome(again), false);
  pressed.asked[0].answer(settings("kept", true));
  assert.equal(await outcome(configured), undefined);
  assert.equal(pressed.state.runtimeSettingsDialog.revision, "kept");
});

test("a reload that opens the form takes the place of a dialog that was asked for before, also once the form is closed", async () => {
  const { state, asked, automation, network } = app();
  const wanted = automation.open();
  const reloaded = network.reload();
  asked[1].answer(settings("restored", false));
  assert.equal(await outcome(reloaded), true);
  const form = state.runtimeSettingsDialog;
  form.draft.port = "7895";
  asked[0].answer(rules("kept"));
  assert.equal(await outcome(wanted), undefined);
  assert.equal(state.automationDialog ?? null, null, "the older request opens nothing");
  assert.equal(state.runtimeSettingsDialog, form);
  assert.equal(form.draft.port, "7895");
  // A dialog that shows what it has read is not closed by the form as the
  // form opens, and is overtaken all the same: the reload asked for the form
  // as it opened it, so the older request opens nothing once the form is
  // closed again either.
  const closed = app();
  const older = askForDialog(closed.state);
  const again = closed.network.reload();
  closed.asked[0].answer(settings("restored", false));
  assert.equal(await outcome(again), true);
  closed.network.close();
  assert.equal(older(), false, "closing the form brings back no older request");
});

test("of the two dialogs the one asked for last opens, whichever read ends first", async () => {
  // The shortcuts and network rules, then the network settings.
  for (const first of [0, 1]) {
    const { state, asked, automation, network } = app();
    const [early, late] = [automation.open(), network.open()];
    asked[first].answer(first === 0 ? rules("kept") : settings("kept", true));
    await outcome(first === 0 ? early : late);
    assert.equal(state.automationDialog ?? null, null, "the one that was overtaken is not open in between");
    if (first === 1) state.runtimeSettingsDialog.draft.level = "debug";
    asked[1 - first].answer(first === 0 ? settings("kept", true) : rules("kept"));
    assert.equal(await outcome(first === 0 ? late : early), undefined);
    assert.equal(state.automationDialog ?? null, null, `answered first: ${first}`);
    assert.equal(state.runtimeSettingsDialog.revision, "kept", `answered first: ${first}`);
    assert.equal(state.runtimeSettingsDialog.draft.level, first === 1 ? "debug" : "info", `answered first: ${first}`);
  }
  // The network settings, then the shortcuts and network rules.
  for (const first of [0, 1]) {
    const { state, asked, automation, network } = app();
    const [early, late] = [network.open(), automation.open()];
    asked[first].answer(first === 0 ? settings("kept", true) : rules("kept"));
    await outcome(first === 0 ? early : late);
    assert.equal(state.runtimeSettingsDialog ?? null, null, "the one that was overtaken is not open in between");
    if (first === 1) state.automationDialog.draft.shortcuts.toggle_core = "Control+Shift+P";
    asked[1 - first].answer(first === 0 ? rules("kept") : settings("kept", true));
    assert.equal(await outcome(first === 0 ? late : early), undefined);
    assert.equal(state.runtimeSettingsDialog ?? null, null, `answered first: ${first}`);
    assert.equal(state.automationDialog.snapshot.revision, "kept", `answered first: ${first}`);
    assert.equal(state.automationDialog.draft.shortcuts.toggle_core, first === 1 ? "Control+Shift+P" : undefined, `answered first: ${first}`);
  }
});

test("a reload looks at what is open when its read ends, not when it was pressed", async () => {
  // The form is open at the press, and closed before the read ends.
  const { state, asked, network } = app();
  const configured = network.open();
  asked[0].answer(settings("kept", true));
  await outcome(configured);
  const reloaded = network.reload();
  network.close();
  asked[1].answer(settings("restored", false));
  assert.equal(await outcome(reloaded), true);
  assert.equal(state.runtimeSettingsDialog.revision, "restored");
  // The other dialog likewise.
  const other = app();
  const wanted = other.automation.open();
  other.asked[0].answer(rules("kept"));
  await outcome(wanted);
  const again = other.network.reload();
  other.automation.close();
  other.asked[1].answer(settings("restored", false));
  assert.equal(await outcome(again), true);
  assert.equal(other.state.runtimeSettingsDialog.revision, "restored");
});

test("a form opens nothing over a dialog that opened at once while it read, and one closed again takes nothing from it", async () => {
  const forms = {
    "the network settings": { press: (page) => page.network.open(), answer: () => settings("kept", true), open: (state) => state.runtimeSettingsDialog },
    "the shortcuts and network rules": { press: (page) => page.automation.open(), answer: () => rules("kept"), open: (state) => state.automationDialog },
  };
  for (const [name, form] of Object.entries(forms)) {
    const page = app();
    const { state, asked } = page;
    const pressed = form.press(page);
    // The DNS query opens at once, and the user types a name there.
    const query = { kind: "dns-query", payload: { name: "example.test", type: "A", result: "" } };
    state.glassDialog = query;
    asked[0].answer(form.answer());
    assert.equal(await outcome(pressed), undefined, name);
    assert.equal(state.glassDialog, query, `${name}: the dialog the user types in stays`);
    assert.equal(form.open(state) ?? null, null, name);
    page.dismiss();
    const again = form.press(page);
    state.glassDialog = { ...query };
    // Closed again as Escape and its backdrop close it, with every overlay.
    page.dismiss();
    asked[1].answer(form.answer());
    assert.equal(await outcome(again), undefined, name);
    assert.notEqual(form.open(state) ?? null, null, `${name}: opens once the query was closed again`);
  }
});

test("a form that is overtaken opens nothing, and the page shows what it read", async () => {
  const { state, asked, logs, page, automation, network } = app();
  const configured = network.open();
  const wanted = automation.open();
  const before = page.renders;
  asked[0].answer(settings("read", true, "debug"));
  assert.equal(await outcome(configured), undefined);
  assert.equal(state.runtimeSettingsDialog, undefined);
  assert.deepEqual([state.runtimeSettings.revision, state.logLevel], ["read", "info"]);
  assert.equal(page.renders, before + 1, "the page is drawn with the settings that were read");
  assert.deepEqual(logs, []);
  asked[1].answer(rules("kept"));
  await outcome(wanted);
  assert.ok(state.automationDialog);
  // A read that fails, or finds the saved settings not in force, is said as
  // it is when nothing overtook the form.
  const failing = app();
  const [refused, held] = [failing.network.open(), failing.network.open()];
  failing.asked[0].refuse(new Error("runtime settings unavailable"));
  assert.equal(await outcome(refused), undefined);
  failing.asked[1].answer(settings("restored", false));
  assert.equal(await outcome(held), undefined);
  assert.equal(failing.state.runtimeSettingsDialog, undefined);
  assert.deepEqual(failing.logs, ["error: runtime settings unavailable", `error: ${savedSettingsNotInForce()}`]);
});

test("a press that is not taken asks for no dialog", async () => {
  // The network is busy, or a migration owns it: the button does nothing,
  // and takes the place of no dialog that is under way.
  for (const held of ["engineMutationBusy", "migrationHandoff"]) {
    const { state, asked, automation, network } = app();
    const reloaded = network.reload();
    state[held] = true;
    assert.equal(await outcome(network.open()), undefined, held);
    if (held === "migrationHandoff") assert.equal(await outcome(automation.open()), undefined);
    assert.equal(asked.length, 1, held);
    state[held] = false;
    asked[0].answer(settings("restored", false));
    assert.equal(await outcome(reloaded), true, held);
    assert.equal(state.runtimeSettingsDialog.revision, "restored", held);
  }
});

test("dismissing the overlays while a form reads ends the request of neither form", async () => {
  // A form that still reads is not open yet: what Escape or a backdrop
  // dismisses then is another dialog, and the form opens when its read ends.
  const { state, asked, automation, network, dismiss } = app();
  const wanted = automation.open();
  dismiss();
  const reloaded = network.reload();
  asked[0].answer(rules("kept"));
  assert.equal(await outcome(wanted), undefined);
  assert.equal(state.automationDialog?.snapshot.revision, "kept", "the shortcuts and network rules open");
  dismiss();
  // The form's button is pressed, and every overlay is dismissed once more
  // while that read is under way.
  const configured = network.open();
  dismiss();
  asked[1].answer(settings("restored", false));
  assert.equal(await outcome(reloaded), false, "the button was pressed after the reload");
  asked[2].answer(settings("kept", true));
  assert.equal(await outcome(configured), undefined);
  assert.equal(state.runtimeSettingsDialog.revision, "kept");
});

test("Connection Info that the Connections page shows again is one of the dialogs a read looks at", () => {
  const away = { activePage: "general", connections: [{ id: "c1" }], connectionDetailId: "c1" };
  const latest = askForDialog(away);
  away.activePage = "connections";
  assert.equal(latest(), false, "a dialog asked for elsewhere opens nothing over Info that its page shows again");
  away.activePage = "general";
  assert.equal(latest(), true, "Info is not shown on another page");
  away.activePage = "connections";
  away.connectionPanel = "diagnostics";
  assert.equal(latest(), true, "nor on the panel of diagnostics");
  away.connectionPanel = "live";
  away.connections = [];
  away.activePage = "connections";
  assert.equal(latest(), true, "nor once its connection is gone");
  const shown = { activePage: "connections", connections: [{ id: "c1" }], connectionDetailId: "c1" };
  assert.equal(askForDialog(shown)(), true, "Info that was shown when the dialog was asked for takes nothing from it");
  assert.deepEqual(openOverlays(shown), [], "and it is none of the overlays");
});
