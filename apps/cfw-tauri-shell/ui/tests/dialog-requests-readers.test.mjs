// The dialogs that show what they have read, in the order of requests they
// share with the network settings form and the shortcuts and network rules:
// the review of unused credentials, the network interfaces, the configuration
// preview, the migration of a legacy profile and the subscription URL of an
// invalid profile. Each is asked for at its press and opens only while it is
// the dialog that was asked for last, so its answer never opens it over a
// dialog that was asked for after it.
import { dom, host, settle, spy } from "./support/fake-host.mjs";
import { runEngine, stopEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state } from "../src/state.js";
import { askForDialog, watchDialogRequests } from "../src/dialog-requests.js";
import { createCredentialSetup } from "../src/credential-setup.js";
import { createDiagnosticsDialogs } from "../src/diagnostics-dialogs.js";
import { createLegacyMigrationDialog } from "../src/legacy-migration-dialog.js";
import { createProfileDialogs } from "../src/profile-dialogs.js";
import { loadNetworkDiagnostics } from "../src/system-info.js";

const PREVIEW = "8f14e45f-ceea-4670-a91e-2f0f1d5e6a7b";
const INVALID = "5d1f4e9c-1c1a-4a2b-8f3d-2b6f9c0a7e11";
const SOURCE = "https://subscription.example/private-test-value";
const UNUSED = Object.freeze({ preview_id: PREVIEW, orphan_count: 1, orphan_references: [{ id: "34db18b6-9903-4e9f-8854-15648e19e4f3", kind: "trojan_password" }] });
const LEGACY = Object.freeze({ status: "ready", preview_id: PREVIEW, name: "iKuuu", source_host: "example.test", legacy_bytes: 2048, active: true });
const logged = () => state.logs.map((entry) => entry.message);

/// The dialogs that read first. Each has the press that asks for it, the
/// command it reads with, an answer that opens it, the kind of the dialog
/// that answer opens, and what a refused read leaves: a dialog that says so,
/// a line in the log, or a rejection that its caller logs.
function readers(overrides = {}) {
  const page = () => ({ renderPage: spy(), renderGlassOverlays: spy(), closeGlassOverlays: spy() });
  const credentials = createCredentialSetup(page());
  const diagnostics = createDiagnosticsDialogs({ ...page(), runtimeProjectionActionAllowed: () => true, ...overrides });
  const legacy = createLegacyMigrationDialog({ ...page(), loadProfilesSnapshot: spy(async () => true), applyActiveProfile: spy(async () => ({ applied: true })) });
  const profiles = createProfileDialogs({ ...page(), closeGlassDialog: spy(), loadProfilesSnapshot: spy(async () => true), invokeProfileChange: spy(), forgetProfileSource: spy() });
  return [
    { name: "the review of unused credentials", press: () => credentials.actions["preview-credential-gc"](), command: "preview_credential_gc",
      answer: UNUSED, kind: "credential-cleanup", refused: "dialog" },
    { name: "the network interfaces", press: () => diagnostics.actions["show-network-interfaces"](), command: "network_diagnostics",
      answer: { services: [] }, kind: "network-services", refused: "log" },
    { name: "the configuration preview", press: () => diagnostics.actions["preview-runtime-config"](), command: "read_runtime_config_text",
      answer: "{}", kind: "preview-config", refused: "log" },
    { name: "the migration of a legacy profile", press: () => legacy.actions["migrate-legacy-profiles"](), command: "preview_legacy_cfw_profile_migration",
      answer: LEGACY, kind: "legacy-profile-migration", refused: "dialog" },
    { name: "the subscription URL of an invalid profile", press: () => profiles.showInvalidProfileSource(INVALID), command: "read_profile_source_url",
      answer: SOURCE, kind: "invalid-profile-source", refused: "rejection" },
  ];
}
const reader = (command, overrides) => readers(overrides).find((item) => item.command === command);

/// Presses for `item` while the host holds its answer. `answer` gives it.
async function pressHeld(item) {
  let answer = null;
  host.respond(item.command, () => new Promise((resolve) => { answer = resolve; }));
  const pressed = item.press();
  await settle();
  assert.equal(typeof answer, "function", `${item.name} reads`);
  return { pressed, answer };
}

beforeEach(() => {
  host.reset();
  dom.reset();
  state.logs = [];
  state.glassDialog = null;
  state.credentialGcPreview = null;
  state.legacyProfileMigrationPreview = null;
  state.profilesUnavailableReason = null;
  state.invalidProfiles = [{ id: INVALID, name: "Reality node" }];
  state.networkDiagnostics = null;
  state.activePage = "general";
  stopEngine();
});

test("a dialog that reads first is asked for at its press, and opens when its read ends", async () => {
  for (const item of readers()) {
    const undisturbed = watchDialogRequests(state);
    const { pressed, answer } = await pressHeld(item);
    assert.equal(undisturbed(), false, `${item.name} is asked for before its read ends`);
    assert.equal(state.glassDialog, null, `${item.name} is not open before its read ends`);
    answer(item.answer);
    await pressed;
    assert.equal(state.glassDialog?.kind, item.kind, item.name);
    state.glassDialog = null;
  }
  assert.deepEqual(state.credentialGcPreview?.previewId, PREVIEW);
  assert.deepEqual(state.legacyProfileMigrationPreview, LEGACY);
});

test("one that is overtaken opens nothing, and keeps nothing of what it read for its dialog", async () => {
  // The review of unused credentials cancels the cleanup that it prepared and
  // that no press shows; no other read leaves anything on the host.
  host.respond("cancel_credential_gc", null);
  for (const item of readers()) {
    const before = host.argsOf("cancel_credential_gc").length;
    const { pressed, answer } = await pressHeld(item);
    // Another dialog is asked for while this one reads.
    const other = askForDialog(state);
    answer(item.answer);
    await pressed;
    assert.equal(state.glassDialog, null, item.name);
    assert.equal(other(), true, `${item.name} asks for nothing more`);
    assert.deepEqual(logged(), [], `${item.name} says nothing`);
    const cancels = item.command === "preview_credential_gc" ? [{ previewId: PREVIEW }] : [];
    assert.deepEqual(host.argsOf("cancel_credential_gc").slice(before), cancels, `${item.name} cancels only what it prepared`);
  }
  assert.equal(state.credentialGcPreview, null);
  assert.equal(state.legacyProfileMigrationPreview, null);
});

test("a read that is refused is logged, and says so in a dialog only for the one that was asked for last", async () => {
  for (const overtaken of [false, true]) {
    for (const item of readers()) {
      state.logs = [];
      const { pressed, answer } = await pressHeld(item);
      if (overtaken) askForDialog(state);
      answer(new Error("the host refuses"));
      if (item.refused === "rejection") {
        await assert.rejects(pressed, /the host refuses/u, item.name);
      } else {
        await pressed;
        assert.equal(logged().filter((message) => message.includes("the host refuses")).length, 1, `${item.name}: the refusal is logged`);
      }
      const shown = !overtaken && item.refused === "dialog" ? "info" : undefined;
      assert.equal(state.glassDialog?.kind, shown, `${item.name}${overtaken ? ", overtaken" : ""}`);
      state.glassDialog = null;
    }
  }
});

test("an invalid profile without a subscription URL says so, also when its dialog was overtaken", async () => {
  for (const overtaken of [false, true]) {
    const { pressed, answer } = await pressHeld(reader("read_profile_source_url"));
    if (overtaken) askForDialog(state);
    answer(null);
    await assert.rejects(pressed, /Reality node has no subscription URL/u, overtaken ? "overtaken" : "asked for last");
    assert.equal(state.glassDialog, null);
  }
});

test("the review of unused credentials pressed again while its read is under way joins that read", async () => {
  // The host reads one review at a time: it holds the profiles across the
  // read, and refuses another meanwhile.
  const item = reader("preview_credential_gc");
  for (const outcomeOfRead of ["answer", "failure"]) {
    state.logs = [];
    let calls = 0;
    let end = null;
    host.respond(item.command, () => {
      calls += 1;
      if (calls > 1) return Promise.reject(new Error("profile repository is busy"));
      return new Promise((resolve, reject) => { end = { answer: () => resolve(item.answer), failure: () => reject(new Error("the vault refuses")) }; });
    });
    const first = item.press();
    await settle();
    const second = item.press();
    await settle();
    end[outcomeOfRead]();
    await Promise.all([first, second]);
    assert.equal(calls, 1, `${outcomeOfRead}: one read`);
    if (outcomeOfRead === "answer") {
      assert.equal(state.glassDialog?.kind, item.kind);
      assert.deepEqual(logged(), []);
    } else {
      assert.equal(state.glassDialog?.kind, "info");
      assert.equal(logged().filter((message) => message.includes("the vault refuses")).length, 1, "logged once");
    }
    state.glassDialog = null;
  }
  // Once a read has ended, a press reads again.
  host.reset();
  host.respond(item.command, item.answer);
  await item.press();
  await item.press();
  assert.equal(host.commands().filter((command) => command === item.command).length, 2);
});

/// The host's observation of the network settings: one at a time. The host
/// lets another wait for the one under way; this one refuses it, so that a
/// page that asked for two at once would fail. Each waits for the test to
/// answer or refuse it.
function observations() {
  const held = [];
  let busy = false;
  host.respond("network_diagnostics", () => {
    if (busy) return Promise.reject(new Error("network diagnostics are already in progress"));
    busy = true;
    return new Promise((resolve, reject) => {
      held.push({
        answer: (value) => { busy = false; resolve(value); },
        refuse: (message) => { busy = false; reject(new Error(message)); },
      });
    });
  });
  return held;
}
const observed = (name) => ({ default_route_interface: name, service_order: [], services: [] });
/// What `promise` came to once the answers given so far are worked off. One
/// that is still under way fails the test in place: Node does not end a test
/// that awaits for good.
async function ended(promise) {
  let outcome = null;
  promise.then((value) => { outcome = { value }; }, (error) => { outcome = { error }; });
  for (let turn = 0; outcome === null && turn < 4; turn += 1) await settle();
  assert.notEqual(outcome, null, "still under way");
  if ("error" in outcome) throw outcome.error;
  return outcome.value;
}

test("the network interfaces pressed again while the host observes open on its next observation", async () => {
  const item = reader("network_diagnostics");
  const held = observations();
  const first = item.press();
  await settle();
  const second = item.press();
  await settle();
  assert.equal(held.length, 1, "the host is asked for no second observation while one is under way");
  held[0].answer(observed("en0"));
  await ended(first);
  assert.equal(state.glassDialog, null, "the first press was overtaken");
  assert.equal(state.networkDiagnostics?.default_route_interface, "en0");
  assert.equal(held.length, 2, "the next observation begins once that one has ended");
  held[1].answer(observed("en1"));
  await ended(second);
  assert.equal(state.glassDialog?.payload?.default_route_interface, "en1");
  assert.equal(state.networkDiagnostics?.default_route_interface, "en1");
  assert.deepEqual(logged(), []);
});

test("every read asked for while the host observes shares its next observation, the page's own as well", async () => {
  const item = reader("network_diagnostics");
  const held = observations();
  const loaded = loadNetworkDiagnostics();
  await settle();
  const pressed = item.press();
  const reloaded = loadNetworkDiagnostics();
  await settle();
  held[0].answer(observed("en0"));
  await ended(loaded);
  assert.equal(held.length, 2, "one more observation answers both reads asked for meanwhile");
  held[1].refuse("the system configuration refuses");
  await ended(pressed);
  await ended(reloaded);
  assert.equal(held.length, 2);
  assert.equal(state.glassDialog, null);
  assert.equal(state.networkDiagnostics, null, "Settings says that the network settings could not be read");
  assert.equal(logged().filter((message) => message.includes("the system configuration refuses")).length, 2, "each read says that it failed");
  // With no observation under way, a read asks the host at once.
  const again = item.press();
  await settle();
  assert.equal(held.length, 3);
  held[2].answer(observed("en2"));
  await ended(again);
  assert.equal(state.glassDialog?.payload?.default_route_interface, "en2");
  assert.equal(state.networkDiagnostics?.default_route_interface, "en2");
});

test("Settings shows what the observation that ended last found, and none after one that failed", async () => {
  const item = reader("network_diagnostics");
  const held = observations();
  const first = loadNetworkDiagnostics();
  await settle();
  const second = loadNetworkDiagnostics();
  await settle();
  held[0].answer(observed("en0"));
  await ended(first);
  const pressed = item.press();
  await settle();
  // The observation after the second is answered as soon as it is asked for.
  host.respond("network_diagnostics", observed("en1"));
  held[1].refuse("the system configuration refuses");
  await ended(second);
  await ended(pressed);
  assert.equal(state.glassDialog?.payload?.default_route_interface, "en1");
  assert.equal(state.networkDiagnostics?.default_route_interface, "en1", "Settings shows the observation after the one that failed");
  // One that failed leaves Settings without network settings, also when only a dialog asked for it.
  state.glassDialog = null;
  host.respond("network_diagnostics", new Error("the system configuration refuses"));
  await ended(item.press());
  assert.equal(state.networkDiagnostics, null);
  assert.equal(state.glassDialog, null);
});

/// The DNS query of General, which opens at once: nothing is read first.
const queryDialog = () => createDiagnosticsDialogs({ renderPage: spy(), renderGlassOverlays: spy(), closeGlassOverlays: spy(),
  runtimeProjectionActionAllowed: () => true }).actions["dns-query"]();

test("one that reads first opens nothing over a dialog that opened at once while it read, also when its read is refused", async () => {
  for (const refused of [false, true]) {
    for (const item of readers()) {
      state.logs = [];
      const { pressed, answer } = await pressHeld(item);
      await queryDialog();
      const typed = state.glassDialog;
      typed.payload.name = "example.test";
      answer(refused ? new Error("the host refuses") : item.answer);
      if (refused && item.refused === "rejection") await assert.rejects(pressed, /the host refuses/u, item.name);
      else await pressed;
      const name = `${item.name}${refused ? ", refused" : ""}`;
      assert.equal(state.glassDialog, typed, `${name}: the dialog the user types in stays`);
      assert.equal(typed.payload.name, "example.test", name);
      state.glassDialog = null;
    }
  }
  assert.equal(state.credentialGcPreview, null);
  assert.equal(state.legacyProfileMigrationPreview, null);
});

test("a dialog that opened at once and was closed again before the read ended takes nothing from it", async () => {
  for (const item of readers()) {
    const { pressed, answer } = await pressHeld(item);
    await queryDialog();
    state.glassDialog = null;
    answer(item.answer);
    await pressed;
    assert.equal(state.glassDialog?.kind, item.kind, item.name);
    state.glassDialog = null;
  }
});

test("a press that is not taken asks for no dialog and reads nothing", async () => {
  const undisturbed = watchDialogRequests(state);
  await reader("read_runtime_config_text", { runtimeProjectionActionAllowed: () => false }).press();
  const legacy = reader("preview_legacy_cfw_profile_migration");
  state.profilesUnavailableReason = "repository locked";
  await legacy.press();
  state.profilesUnavailableReason = null;
  runEngine();
  await legacy.press();
  stopEngine();
  state.invalidProfiles = [];
  await assert.rejects(reader("read_profile_source_url").press(), /profile not found/u);
  assert.equal(undisturbed(), true);
  assert.deepEqual(host.commands(), []);
  assert.equal(state.glassDialog, null);
});

/// The counts of the renders of the page and of the overlays alone.
const drawn = (shown) => [shown.renderPage.count(), shown.renderGlassOverlays.count()];

test("the network interfaces draw Settings as they open, which shows what they observed, and only their dialog elsewhere", async () => {
  for (const [page, renders] of [["settings", [1, 0]], ["general", [0, 1]], ["profiles", [0, 1]]]) {
    state.activePage = page;
    const shown = { renderPage: spy(), renderGlassOverlays: spy(), closeGlassOverlays: spy() };
    const diagnostics = createDiagnosticsDialogs({ ...shown, runtimeProjectionActionAllowed: () => true });
    host.respond("network_diagnostics", observed("en7"));
    await ended(diagnostics.actions["show-network-interfaces"]());
    assert.equal(state.glassDialog.kind, "network-services", page);
    assert.deepEqual(state.networkDiagnostics, observed("en7"));
    assert.deepEqual(drawn(shown), renders, page);
    state.glassDialog = null;
  }
});

test("an overtaken read draws Settings for the observation of the interfaces, and no page that shows nothing of it", async () => {
  for (const [page, interfaces] of [["settings", [1, 0]], ["profiles", [0, 0]]]) {
    for (const [command, renders] of [["network_diagnostics", interfaces], ["read_runtime_config_text", [0, 0]]]) {
      state.activePage = page;
      const shown = { renderPage: spy(), renderGlassOverlays: spy(), closeGlassOverlays: spy() };
      const item = reader(command, shown);
      const { pressed, answer } = await pressHeld(item);
      askForDialog(state);
      answer(item.answer);
      await ended(pressed);
      assert.equal(state.glassDialog, null, `${item.name} on ${page}`);
      assert.deepEqual(drawn(shown), renders, `${item.name} on ${page}`);
    }
  }
});

test("a failed read draws the pages that say so, Settings and the log for the interfaces and the log for the preview, and no other", async () => {
  for (const [page, interfaces, preview] of [["settings", 1, 0], ["logs", 1, 1], ["general", 0, 0], ["profiles", 0, 0]]) {
    for (const [command, renders] of [["network_diagnostics", interfaces], ["read_runtime_config_text", preview]]) {
      state.activePage = page;
      const shown = { renderPage: spy(), renderGlassOverlays: spy(), closeGlassOverlays: spy() };
      const item = reader(command, shown);
      host.respond(command, new Error("refused"));
      await ended(item.press());
      assert.equal(state.glassDialog, null, `${item.name} on ${page}`);
      assert.deepEqual(drawn(shown), [renders, 0], `${item.name} on ${page}`);
    }
  }
  assert.equal(logged().length, 8, "each failure is logged");
});

test("a review of unused credentials that no press shows cancels its cleanup once, and one that a later press shows keeps it", async () => {
  const item = reader("preview_credential_gc");
  /// Holds each read of the review until `answers` gives it.
  const held = (answers) => host.respond(item.command, () => new Promise((resolve) => { answers.push(resolve); }));
  const cancelled = () => host.argsOf("cancel_credential_gc");
  for (const presses of [1, 2]) {
    host.reset();
    const answers = [];
    held(answers);
    host.respond("cancel_credential_gc", null);
    const pressed = Array.from({ length: presses }, () => item.press());
    await settle();
    assert.equal(answers.length, 1, `${presses} presses share one read`);
    askForDialog(state);
    answers[0](item.answer);
    await ended(Promise.all(pressed));
    assert.deepEqual(cancelled(), [{ previewId: PREVIEW }], `${presses} presses overtaken: cancelled once`);
    assert.equal(state.glassDialog, null);
  }
  host.reset();
  const answers = [];
  held(answers);
  host.respond("cancel_credential_gc", null);
  const first = item.press();
  await settle();
  const second = item.press();
  await settle();
  assert.equal(answers.length, 1, "the later press joins the read");
  answers[0](item.answer);
  await ended(Promise.all([first, second]));
  assert.deepEqual(cancelled(), [], "the cleanup that the later press shows is kept");
  assert.equal(state.glassDialog?.kind, item.kind);
  state.glassDialog = null;
  for (const answer of [{ ...UNUSED, orphan_count: 0, orphan_references: [] }, UNUSED]) {
    host.reset();
    state.logs = [];
    const refused = answer.orphan_count !== 0;
    host.respond(item.command, answer);
    host.respond("cancel_credential_gc", new Error("the cleanup is already gone"));
    const pressed = item.press();
    askForDialog(state);
    await ended(pressed);
    assert.equal(cancelled().length, refused ? 1 : 0, refused ? "an overtaken cleanup is cancelled" : "an empty one has none");
    assert.equal(logged().includes("the cleanup is already gone"), refused, "a refused cancellation is logged");
  }
});
