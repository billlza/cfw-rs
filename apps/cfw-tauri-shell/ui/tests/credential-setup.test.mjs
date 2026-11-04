import { dom, element, host, spy } from "./support/fake-host.mjs";
import { runEngine, stopEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state } from "../src/state.js";
import { createCredentialSetup } from "../src/credential-setup.js";

const FIRST = { id: "34db18b6-9903-4e9f-8854-15648e19e4f3", kind: "trojan_password" };
const SECOND = { id: "5d1f4e9c-1c1a-4a2b-8f3d-2b6f9c0a7e11", kind: "vmess_uuid" };
const PREVIEW = "8f14e45f-ceea-4670-a91e-2f0f1d5e6a7b";
const lastLog = () => state.logs[0];

function setup(overrides = {}) {
  const d = { renderPage: spy(), renderGlassOverlays: spy(), closeGlassOverlays: spy(), ...overrides };
  return { d, credentials: createCredentialSetup(d) };
}

beforeEach(() => {
  host.reset();
  dom.reset();
  state.logs = [];
  state.profiles = [{ id: "work", name: "Work", active: true }];
  state.credentialSetup = null;
  state.credentialGcPreview = null;
  state.glassDialog = null;
  stopEngine();
});

test("credential setup asks the vault which references are missing", async () => {
  const { d, credentials } = setup();
  host.respond("profile_credential_requirements", [FIRST, SECOND]);
  host.respond("profile_credential_presence", [{ reference: FIRST, present: true }, { reference: SECOND, present: false }]);
  await credentials.openCredentialSetup("work");
  assert.deepEqual(state.credentialSetup, {
    profileId: "work", profileName: "Work", requiredCount: 2, presentCount: 1, missing: [SECOND], vaultAvailable: true, error: null,
  });
  assert.equal(d.renderGlassOverlays.count(), 2, "the dialog opens, then shows the answer");
  await assert.rejects(() => credentials.openCredentialSetup("ghost"), /profile not found: ghost/u);
});

test("a profile without references asks no presence question", async () => {
  const { credentials } = setup();
  host.respond("profile_credential_requirements", []);
  await credentials.openCredentialSetup("work");
  assert.equal(state.credentialSetup.requiredCount, 0);
  assert.deepEqual(host.commands(), ["profile_credential_requirements"]);
  const html = credentials.dialogs.render({ kind: "credentials" });
  assert.match(html, /This profile references no credentials\./u);
});

test("an unavailable vault assumes nothing present or missing and offers no submission", async () => {
  const { d, credentials } = setup();
  host.respond("profile_credential_requirements", new Error("vault locked"));
  await credentials.openCredentialSetup("work");
  assert.equal(state.credentialSetup.vaultAvailable, false);
  assert.deepEqual(state.credentialSetup.missing, []);
  assert.equal(lastLog().message, "Could not verify credentials for Work: vault locked");
  const html = credentials.dialogs.render({ kind: "credentials" });
  assert.match(html, /Credential presence could not be verified[^<]*vault locked/u);
  assert.doesNotMatch(html, /data-glass-credentials-confirm/u);
  host.respond("profile_credential_requirements", () => {
    state.glassDialog = { kind: "info" };
    return new Error("vault locked");
  });
  await credentials.openCredentialSetup("work");
  assert.equal(d.renderGlassOverlays.count(), 3, "a dialog replaced meanwhile is not rendered again");
});

test("the credentials dialog asks only for missing values, and only with the core stopped", () => {
  const { credentials } = setup();
  assert.match(credentials.dialogs.render({ kind: "credentials" }), /Reading credential requirements…/u);
  state.credentialSetup = { profileId: "work", profileName: "Work", requiredCount: 2, presentCount: 2, missing: [], vaultAvailable: true, error: null };
  assert.match(credentials.dialogs.render({ kind: "credentials" }), /All 2 credential reference\(s\) are already present in the vault\./u);
  state.credentialSetup = { profileId: "work", profileName: "Work", requiredCount: 2, presentCount: 1, missing: [SECOND], vaultAvailable: true, error: null };
  let html = credentials.dialogs.render({ kind: "credentials" });
  assert.match(html, /1 of 2 reference\(s\) are already present/u);
  assert.match(html, /type="password"[^>]*data-credential-index="0"/u);
  assert.match(html, /data-glass-credentials-confirm="work"/u);
  runEngine();
  html = credentials.dialogs.render({ kind: "credentials" });
  assert.doesNotMatch(html, /data-glass-credentials-confirm/u);
  assert.match(html, /Stop the core before credential maintenance/u);
  state.credentialSetup = { profileId: "work", vaultAvailable: false, missing: [], error: null };
  assert.match(credentials.dialogs.render({ kind: "credentials" }), /The credential vault is unavailable\./u);
  assert.throws(() => credentials.dialogs.render({ kind: "copy" }), /credential dialog copy is unknown/u);
});

test("stored credentials leave the renderer whether or not the vault accepted them", async () => {
  const { d, credentials } = setup();
  state.credentialSetup = { profileId: "work", profileName: "Work", requiredCount: 1, presentCount: 0, missing: [FIRST], vaultAvailable: true, error: null };
  const confirm = element("button", { dataset: { glassCredentialsConfirm: "work" } });
  const other = element("button", { dataset: { glassCredentialsConfirm: "home" } });
  dom.setAll("[data-glass-credentials-confirm]", [confirm, other]);
  const secret = element("input", { dataset: { credentialIndex: "0" }, value: "hunter2" });
  dom.setAll("[data-credential-secret]", [secret]);
  credentials.dialogs.bind();
  await other.fire("click");
  assert.deepEqual(host.commands(), [], "a button for another profile does nothing");

  let provisioned;
  host.respond("provision_profile_credentials", (args) => {
    provisioned = structuredClone(args);
    return { profile_id: "work" };
  });
  await confirm.fire("click");
  assert.deepEqual(provisioned, { profileId: "work", credentials: [{ reference: FIRST, secret: "hunter2" }] });
  assert.equal(secret.value, "", "the field is cleared");
  assert.equal(state.credentialSetup, null);
  assert.equal(d.closeGlassOverlays.count(), 1);
  assert.equal(lastLog().message, "Stored 1 credential reference(s) for Work");

  state.credentialSetup = { profileId: "work", profileName: "Work", requiredCount: 1, presentCount: 0, missing: [FIRST], vaultAvailable: true, error: null };
  secret.value = "hunter2";
  host.respond("provision_profile_credentials", { profile_id: "home" });
  await confirm.fire("click");
  assert.equal(lastLog().message, "credential receipt does not match the profile");
  assert.equal(secret.value, "");
  assert.notEqual(state.credentialSetup, null, "a refused batch keeps the dialog's setup");

  await confirm.fire("click");
  assert.equal(lastLog().message, "Trojan Password is required");
  assert.equal(d.renderPage.count(), 3);
});

test("credential cleanup previews unused entries, deletes them once and cancels a preview", async () => {
  const { d, credentials } = setup();
  host.respond("preview_credential_gc", { preview_id: PREVIEW, orphan_count: 1, orphan_references: [FIRST] });
  await credentials.actions["preview-credential-gc"]();
  assert.equal(state.credentialGcPreview.orphanCount, 1);
  assert.deepEqual(state.glassDialog, { kind: "credential-cleanup" });
  let html = credentials.dialogs.render({ kind: "credential-cleanup" });
  assert.match(html, /Unused Keychain entries: 1/u);
  assert.match(html, /<li>Trojan Password · 34db18b6/u);
  assert.match(html, /data-glass-credential-gc-confirm/u);

  host.respond("preview_credential_gc", { preview_id: PREVIEW, orphan_count: 0, orphan_references: [] });
  await credentials.actions["preview-credential-gc"]();
  assert.equal(state.credentialGcPreview, null, "nothing unused, nothing to delete");
  html = credentials.dialogs.render({ kind: "credential-cleanup" });
  assert.match(html, /has no unused references/u);
  assert.doesNotMatch(html, /data-glass-credential-gc-confirm/u);

  const confirm = element("button");
  const cancel = element("button");
  dom.setAll("[data-glass-credential-gc-confirm]", [confirm]);
  dom.setAll("[data-glass-credential-gc-cancel]", [cancel]);
  credentials.dialogs.bind();
  await confirm.fire("click");
  assert.deepEqual(host.argsOf("commit_credential_gc"), [], "no preview, no deletion");

  state.credentialGcPreview = { previewId: PREVIEW, orphanCount: 1, orphanReferences: [FIRST] };
  host.respond("commit_credential_gc", { removed_count: 1 });
  await confirm.fire("click");
  assert.equal(lastLog().message, "Removed 1 unused credential reference(s)");
  assert.equal(state.credentialGcPreview, null);

  state.credentialGcPreview = { previewId: PREVIEW, orphanCount: 2, orphanReferences: [FIRST, SECOND] };
  host.respond("commit_credential_gc", { removed_count: 1 });
  await confirm.fire("click");
  assert.equal(lastLog().message, "credential cleanup receipt does not match the preview");
  assert.equal(state.credentialGcPreview, null, "a preview is one-shot either way");

  state.credentialGcPreview = { previewId: PREVIEW, orphanCount: 1, orphanReferences: [FIRST] };
  host.respond("cancel_credential_gc", null);
  await cancel.fire("click");
  assert.deepEqual(host.argsOf("cancel_credential_gc"), [{ previewId: PREVIEW }]);
  state.credentialGcPreview = { previewId: PREVIEW, orphanCount: 1, orphanReferences: [FIRST] };
  host.respond("cancel_credential_gc", new Error("already expired"));
  await cancel.fire("click");
  assert.equal(lastLog().message, "already expired");
  await cancel.fire("click");
  assert.equal(host.argsOf("cancel_credential_gc").length, 2, "a closed cleanup has nothing to cancel");
  assert.equal(d.closeGlassOverlays.count(), 5);
});

test("a refused cleanup preview is shown where it was asked for", async () => {
  const { d, credentials } = setup();
  host.respond("preview_credential_gc", new Error("invalid profiles are listed"));
  await credentials.actions["preview-credential-gc"]();
  assert.deepEqual(state.glassDialog, {
    kind: "info",
    payload: { title: "Unused credentials", body: "Credential cleanup is unavailable: invalid profiles are listed" },
  });
  assert.equal(lastLog().message, "invalid profiles are listed");
  assert.equal(d.renderGlassOverlays.count(), 1);
});
