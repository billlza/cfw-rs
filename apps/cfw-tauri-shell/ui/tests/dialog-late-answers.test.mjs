// What a dialog reads for itself once it is open, and what the vault answers
// for the dialog of credentials, is shown in the dialog it was asked from
// while that one is open, and in no other: the answer of a DNS query, a check
// for updates, a failed migration of a legacy profile, the credentials that a
// profile is missing. One that ends once its dialog was closed, or another
// took its place, opens nothing. It would open its dialog again over what the
// user opened since, and keep a dialog that was asked for meanwhile from
// opening, as a dialog that opened while that one read. The checks for
// updates and the openings of the download page are taken in the order they
// began, and a check asked for while one is under way joins it.
import { dom, element, host, settle, spy } from "./support/fake-host.mjs";
import { runEngine, stopEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state } from "../src/state.js";
import { createCredentialSetup } from "../src/credential-setup.js";
import { createDiagnosticsDialogs } from "../src/diagnostics-dialogs.js";
import { createLegacyMigrationDialog } from "../src/legacy-migration-dialog.js";
import { createUpdateController } from "../src/update-controller.js";
import { outcome } from "./support/outcome.mjs";

const WORK = Object.freeze({ id: "34db18b6-9903-4e9f-8854-15648e19e4f3", kind: "trojan_password" });
const HOME = Object.freeze({ id: "5d1f4e9c-1c1a-4a2b-8f3d-2b6f9c0a7e11", kind: "vmess_uuid" });
const PREVIEW = "8f14e45f-ceea-4670-a91e-2f0f1d5e6a7b";
const page = () => ({ renderPage: spy(), renderGlassOverlays: spy(), closeGlassOverlays: spy() });
const logged = () => state.logs.map((entry) => entry.message);

/// A command the host answers once the test says so.
function held(command) {
  const answer = {};
  host.respond(command, () => new Promise((resolve, reject) => Object.assign(answer, { resolve, reject })));
  return answer;
}

/// The checks for updates of a host that makes one at a time and refuses
/// another meanwhile, as `check_for_updates` does. Each is answered once the
/// test says so.
function heldChecks() {
  const checks = [];
  host.respond("check_for_updates", () => {
    if (checks.some((check) => !check.ended)) {
      return Promise.reject(new Error("an update check or release-page authorization is already in progress"));
    }
    return new Promise((resolve, reject) => {
      const check = { ended: false };
      check.resolve = (value) => { check.ended = true; resolve(value); };
      check.reject = (error) => { check.ended = true; reject(error); };
      checks.push(check);
    });
  });
  return checks;
}

beforeEach(() => {
  host.reset();
  dom.reset();
  state.logs = [];
  state.glassDialog = null;
  state.credentialSetup = null;
  state.updateInfo = null;
  state.payload = { product: { name: "Clash for Mac", version: "0.5.1", license: "GPL-3.0-or-later", operating_system: "macos", architecture: "arm64", minimum_os_version: "15.0" }, native_ui: {} };
  state.profiles = [{ id: "work", name: "Work" }, { id: "home", name: "Home" }];
  stopEngine();
});

/// The DNS query, opened, with its Query button bound as the overlay layer binds it.
async function openQuery(dialogs) {
  await dialogs.actions["dns-query"]();
  const confirm = element("button");
  dom.setAll("[data-glass-dns-confirm]", [confirm]);
  dom.set("[data-glass-dns-name]", element("input", { value: "example.test" }));
  dialogs.dialogs.bind();
  return { query: state.glassDialog, confirm };
}

test("the answer of a DNS query is shown in the query it was asked from, which keeps its place", async () => {
  const dialogs = createDiagnosticsDialogs({ ...page(), runtimeProjectionActionAllowed: () => true });
  const { query, confirm } = await openQuery(dialogs);
  await confirm.fire("click");
  assert.equal(state.glassDialog, query, "the engine is off");
  assert.equal(query.payload.result, "Engine is Off; start the engine before querying DNS.");
  runEngine();
  for (const [answer, result] of [[{ answers: ["192.0.2.1"] }, /192\.0\.2\.1/u], [new Error("NXDOMAIN"), /^NXDOMAIN$/u]]) {
    host.respond("dns_query", answer);
    await confirm.fire("click");
    assert.equal(state.glassDialog, query, String(result));
    assert.match(query.payload.result, result);
  }
});

test("a DNS answer that ends once its query was closed opens nothing, and a dialog asked for meanwhile opens", async () => {
  runEngine();
  const shown = page();
  const dialogs = createDiagnosticsDialogs({ ...shown, runtimeProjectionActionAllowed: () => true });
  for (const failed of [false, true]) {
    const { confirm } = await openQuery(dialogs);
    const answer = held("dns_query");
    const asked = confirm.fire("click");
    await settle();
    // The query is closed, and the configuration preview asked for while it reads.
    state.glassDialog = null;
    const preview = held("read_runtime_config_text");
    const previewed = dialogs.actions["preview-runtime-config"]();
    await settle();
    const drawn = shown.renderGlassOverlays.count();
    if (failed) answer.reject(new Error("NXDOMAIN"));
    else answer.resolve({ answers: ["192.0.2.1"] });
    await asked;
    assert.equal(state.glassDialog, null, `the closed query is not opened again (failed: ${failed})`);
    assert.equal(shown.renderGlassOverlays.count(), drawn, `nothing is drawn over what is open (failed: ${failed})`);
    preview.resolve("{}");
    await previewed;
    assert.deepEqual(state.glassDialog, { kind: "preview-config", payload: "{}" }, `failed: ${failed}`);
  }
  assert.deepEqual(logged(), ["DNS query failed: NXDOMAIN"], "a failure is still logged");
});

test("a check for updates that ends once the About dialog was closed, or another took its place, opens nothing", async () => {
  const controller = createUpdateController({ ...page(), overlayOpen: () => false });
  const info = { kind: "info", payload: { title: "Allow LAN", body: "" } };
  for (const [answer, found, since] of [[{ available: true, version: "0.5.2", current: "0.5.1" }, "0.5.2", null], [new Error("rate limited"), null, info]]) {
    const check = held("check_for_updates");
    const pressed = controller.actions["check-for-updates"]();
    await settle();
    assert.equal(state.glassDialog?.payload?.phase, "checking");
    state.glassDialog = since;
    if (answer instanceof Error) check.reject(answer);
    else check.resolve(answer);
    await pressed;
    assert.equal(state.glassDialog, since, answer instanceof Error ? answer.message : "an update is available");
    assert.equal(state.updateInfo.version, found, "what the check found is still taken");
  }
  assert.equal(state.updateInfo.error, "rate limited");
});

test("the About dialog shows the answer of its own check in place, and nothing once it was closed", async () => {
  const controller = createUpdateController({ ...page(), overlayOpen: () => false });
  state.glassDialog = { kind: "info", payload: { title: "Allow LAN", body: "" } };
  const about = controller.openProductAboutDialog({ phase: "idle" });
  assert.equal(state.glassDialog, about, "it opens in place of another dialog");
  assert.equal(about.kind, "product-about");
  const button = element("button");
  dom.setAll("[data-glass-check-update]", [button]);
  controller.dialogs.bind();
  host.respond("check_for_updates", { available: false, current: "0.5.1" });
  await button.fire("click");
  assert.equal(state.glassDialog, about, "the dialog keeps its place");
  assert.equal(about.payload.update.available, false);
  for (const answer of [new Error("rate limited"), { available: true, version: "0.5.2", current: "0.5.1" }]) {
    state.glassDialog = about;
    const check = held("check_for_updates");
    const pressed = button.fire("click");
    await settle();
    assert.equal(about.payload.phase, "checking");
    state.glassDialog = null;
    if (answer instanceof Error) check.reject(answer);
    else check.resolve(answer);
    await pressed;
    assert.equal(state.glassDialog, null, `a closed dialog is not opened again: ${answer instanceof Error ? answer.message : "an update"}`);
  }

  // The download page of the update could not be opened, once the dialog was closed.
  state.glassDialog = about;
  const open = element("button");
  dom.setAll("[data-glass-open-update]", [open]);
  controller.dialogs.bind();
  const opening = held("open_available_update");
  const opened = open.fire("click");
  await settle();
  state.glassDialog = null;
  opening.reject(new Error("no browser"));
  assert.notEqual(await outcome(opened), "still waiting", "the opening ends with its failure");
  assert.equal(state.glassDialog, null);
  assert.ok(logged().includes("Could not open update: no browser"), "a failure is still logged");
});

test("a failed migration of a legacy profile is said in its dialog while it is open, and only in the log once it was dismissed", async () => {
  const d = { ...page(), loadProfilesSnapshot: spy(async () => true), applyActiveProfile: spy(async () => ({ applied: true })) };
  const legacy = createLegacyMigrationDialog(d);
  const preview = { status: "ready", preview_id: PREVIEW, name: "iKuuu", source_host: "example.test", legacy_bytes: 2048, active: true };
  for (const dismissed of [false, true]) {
    state.glassDialog = { kind: "legacy-profile-migration", payload: preview, busy: false, error: null };
    const confirm = element("button", { dataset: { previewId: PREVIEW } });
    dom.setAll("[data-glass-legacy-migration-confirm]", [confirm]);
    legacy.dialogs.bind();
    const commit = held("commit_legacy_cfw_profile_migration");
    const confirmed = confirm.fire("click");
    await settle();
    if (dismissed) state.glassDialog = null;
    commit.reject(new Error("preview expired"));
    await confirmed;
    if (dismissed) assert.equal(state.glassDialog, null, "nothing opens over what the user opened since");
    else assert.equal(state.glassDialog?.payload?.title, "Legacy migration failed");
    assert.match(logged()[0], /Legacy profile migration failed: preview expired/u);
  }
});

test("what the vault answers of the credentials of a profile is shown only in the dialog of that profile", async () => {
  const shown = page();
  const credentials = createCredentialSetup(shown);
  for (const failed of [false, true]) {
    const requirements = held("profile_credential_requirements");
    const work = credentials.openCredentialSetup("work");
    await settle();
    // Its dialog is closed, and the dialog of another profile opened and answered.
    state.glassDialog = null;
    host.respond("profile_credential_requirements", [HOME]);
    host.respond("profile_credential_presence", [{ reference: HOME, present: false }]);
    await credentials.openCredentialSetup("home");
    const home = state.glassDialog;
    host.respond("profile_credential_presence", [{ reference: WORK, present: false }]);
    const drawn = shown.renderGlassOverlays.count();
    if (failed) requirements.reject(new Error("vault locked"));
    else requirements.resolve([WORK]);
    await work;
    assert.equal(state.glassDialog, home, `failed: ${failed}`);
    assert.equal(shown.renderGlassOverlays.count(), drawn, `nothing is drawn over the dialog of Home (failed: ${failed})`);
    assert.equal(state.credentialSetup.profileId, "home", `failed: ${failed}`);
    assert.deepEqual(state.credentialSetup.missing, [HOME], `failed: ${failed}`);
  }
  assert.deepEqual(logged(), ["Could not verify credentials for Work: vault locked"], "a failure is still logged");
});

test("a check for updates asked for while one is under way joins it, and the dialog that asked shows its answer", async () => {
  const controller = createUpdateController({ ...page(), overlayOpen: () => false });
  const checks = heldChecks();
  const first = controller.actions["check-for-updates"]();
  await settle();
  state.glassDialog = null;
  const second = controller.actions["check-for-updates"]();
  await settle();
  const about = state.glassDialog;
  assert.equal(about?.payload?.phase, "checking", "the dialog asked for since checks");
  // Its own check, pressed meanwhile, joins the same one.
  const button = element("button");
  dom.setAll("[data-glass-check-update]", [button]);
  controller.dialogs.bind();
  const third = button.fire("click");
  await settle();
  assert.equal(host.argsOf("check_for_updates").length, 1, "one check is made");
  checks[0].resolve({ available: true, version: "0.5.2", current: "0.5.1" });
  await Promise.all([first, second, third]);
  assert.equal(state.glassDialog, about, "the dialog keeps its place");
  assert.equal(about.payload.phase, "idle");
  assert.equal(about.payload.update.version, "0.5.2");
  assert.equal(state.updateInfo.version, "0.5.2");
  assert.deepEqual(logged().filter((message) => message.startsWith("Update check failed")), [], "nothing was refused");
});

test("the check made at startup is joined by a check asked for meanwhile, which shows its answer", async () => {
  const controller = createUpdateController({ ...page(), overlayOpen: () => false });
  const checks = heldChecks();
  const startup = controller.checkAtStartup();
  await settle();
  const asked = controller.actions["check-for-updates"]();
  await settle();
  assert.equal(host.argsOf("check_for_updates").length, 1, "one check is made");
  checks[0].reject(new Error("rate limited"));
  await Promise.all([startup, asked]);
  assert.equal(state.glassDialog?.payload?.update?.error, "rate limited", "the dialog shows the failure of the check it joined");
  assert.equal(state.updateInfo.error, "rate limited");
  assert.ok(logged().includes("Automatic update check failed: rate limited"));
  assert.ok(logged().includes("Update check failed: rate limited"));
});

test("an opening of the download page that ends once a later check has begun takes nothing from that check", async () => {
  const controller = createUpdateController({ ...page(), overlayOpen: () => false });
  for (const failed of [true, false]) {
    host.respond("check_for_updates", { available: true, version: "0.5.2", current: "0.5.1" });
    await controller.actions["check-for-updates"]();
    const open = element("button");
    dom.setAll("[data-glass-open-update]", [open]);
    controller.dialogs.bind();
    const opening = held("open_available_update");
    const opened = open.fire("click");
    await settle();
    // Its About dialog is dismissed, and another check is made from a button of a page.
    state.glassDialog = null;
    await controller.actions["check-for-updates"]();
    const about = state.glassDialog;
    assert.equal(about.payload.update.version, "0.5.2");
    if (failed) opening.reject(new Error("no browser"));
    else opening.resolve({ opened: true, installed: false, version: "0.5.2" });
    assert.notEqual(await outcome(opened), "still waiting", `the opening ends (failed: ${failed})`);
    assert.equal(state.glassDialog, about, `failed: ${failed}`);
    assert.equal(about.payload.update.version, "0.5.2", `the dialog shows what the later check found (failed: ${failed})`);
    assert.equal(state.updateInfo.version, "0.5.2", `the app keeps it, so its download can be opened (failed: ${failed})`);
  }
  assert.ok(logged().includes("Could not open update: no browser"), "a failure is still logged");
});

test("a check that ends once an opening of the download page began says what is offered, as the host refused that opening", async () => {
  const controller = createUpdateController({ ...page(), overlayOpen: () => false });
  host.respond("check_for_updates", { available: true, version: "0.5.2", current: "0.5.1" });
  await controller.actions["check-for-updates"]();
  const open = element("button");
  dom.setAll("[data-glass-open-update]", [open]);
  controller.dialogs.bind();
  const checks = heldChecks();
  const checked = controller.actions["check-for-updates"]();
  await settle();
  // The host makes no recheck while it checks.
  host.respond("open_available_update", new Error("an update check or release-page authorization is already in progress"));
  const opened = open.fire("click");
  await settle();
  assert.notEqual(await outcome(opened), "still waiting", "the refused opening ends at once and checks nothing again");
  checks[0].resolve({ available: true, version: "0.5.3", current: "0.5.1" });
  await checked;
  assert.equal(state.updateInfo.version, "0.5.3", "what the check found is offered");
  assert.equal(state.glassDialog.payload.update.version, "0.5.3");
});
