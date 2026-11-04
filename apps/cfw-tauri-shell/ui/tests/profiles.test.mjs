import { dom, element, host, clipboard, settle, spy } from "./support/fake-host.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state, runtime } from "../src/state.js";
import { createProfileActions } from "../src/profile-actions.js";
import { createProfileData } from "../src/profile-data.js";
import { createProfileDialogs } from "../src/profile-dialogs.js";
import { focusProfileEditorSection, openProfileInspector } from "../src/profile-inspector.js";
import { renderProfiles } from "../src/profiles-view.js";

const lastLog = () => state.logs[0];
const messages = () => state.logs.map((entry) => entry.message);

beforeEach(() => {
  host.reset();
  dom.reset();
  clipboard.readError = null;
  clipboard.text = "";
  state.payload = { product: { name: "Clash for Mac", operating_system: "macos" }, native_ui: {} };
  state.profiles = [
    { id: "work", name: "Work", active: false, sourceKind: "subscription", updated: "now" },
    { id: "home", name: "Home", active: true, sourceKind: "local", updated: "now" },
  ];
  state.invalidProfiles = [];
  state.profilesUnavailableReason = null;
  state.profileInspector = null;
  state.glassDialog = null;
  state.credentialSetup = null;
  state.logs = [];
  state.engine = { ...state.engine, active: false, state: "Off", desiredMode: "off" };
});

function actionDeps(overrides = {}) {
  return {
    renderPage: spy(),
    renderGlassOverlays: spy(),
    scheduleRender: spy(),
    runProfileMenuAction: spy(async () => undefined),
    invokeProfileChange: spy(async (command) => ({ id: "new", name: "New", bytes: 2048, command })),
    loadProfilesSnapshot: spy(async () => true),
    selectProfileById: spy(async () => true),
    openCredentialSetup: spy(async () => undefined),
    resolveProfileSource: spy(async (id) => (id === "work" ? "https://example.test/sub" : null)),
    openProfileContextMenu: spy(),
    showInvalidProfileSource: spy(async () => undefined),
    ...overrides,
  };
}

test("importing needs a link; a subscription is imported active, a node link is selected after import", async () => {
  const d = actionDeps();
  const { actions } = createProfileActions(d);
  await actions["import-profile"]();
  assert.match(lastLog().message, /required before import/u);
  assert.equal(d.invokeProfileChange.count(), 0);

  const input = dom.set("[data-profile-url]", element("textarea", { value: "  https://example.test/sub  " }));
  await actions["import-profile"]();
  assert.deepEqual(d.invokeProfileChange.calls[0], ["import_profile_url", { url: "https://example.test/sub", name: null, activate: true }]);
  assert.equal(input.value, "");
  assert.equal(d.selectProfileById.count(), 0, "a subscription import activates itself");
  assert.deepEqual(d.openCredentialSetup.calls, [["new"]]);
  assert.match(messages().find((message) => message.startsWith("Profile imported")), /New \(2\.0 KB\)/u);

  input.value = "socks5://127.0.0.1:1080";
  await actions["import-profile"]();
  assert.deepEqual(d.invokeProfileChange.calls[1], ["import_profile_text", { name: null, body: "socks5://127.0.0.1:1080" }]);
  assert.deepEqual(d.selectProfileById.calls, [["new"]]);
  assert.equal(d.renderPage.count(), 3);
});

test("pasting fills the link box or reports a refused clipboard", async () => {
  const d = actionDeps();
  const { actions } = createProfileActions(d);
  const input = dom.set("[data-profile-url]", element("textarea"));
  clipboard.text = " https://example.test/pasted \n";
  await actions["paste-profile-url"]();
  assert.equal(input.value, "https://example.test/pasted");
  clipboard.readError = new Error("denied");
  await actions["paste-profile-url"]();
  assert.match(lastLog().message, /Clipboard read was refused/u);
  dom.reset();
  clipboard.readError = null;
  await actions["paste-profile-url"]();
  assert.match(lastLog().message, /pasted from clipboard/u, "no box to fill is not an error");
});

test("a local file import asks for a file first, then imports, selects and always clears the picker", async () => {
  const d = actionDeps();
  const { actions } = createProfileActions(d);
  await actions["import-profile-file"]();
  assert.equal(d.renderPage.count(), 0, "no picker, nothing to do");
  const picker = dom.set("[data-profile-file]", element("input"));
  await actions["import-profile-file"]();
  assert.equal(picker.clicked, 1, "without a chosen file the picker opens");
  picker.files = [{ name: "home.json", size: 2, arrayBuffer: async () => new TextEncoder().encode("{}").buffer }];
  picker.value = "home.json";
  await actions["import-profile-file"]();
  assert.deepEqual(d.invokeProfileChange.calls[0], ["import_profile_text", { name: "home.json", body: "{}" }]);
  assert.deepEqual(d.selectProfileById.calls, [["new"]]);
  assert.equal(picker.value, "");
  d.invokeProfileChange = spy(async () => { throw new Error("invalid profile"); });
  picker.value = "home.json";
  await assert.rejects(() => createProfileActions(d).actions["import-profile-file"](), /invalid profile/u);
  assert.equal(picker.value, "", "a refused import still clears the picker");
});

test("a picker change imports the file and reports a refusal", async () => {
  const d = actionDeps({ invokeProfileChange: spy(async () => { throw new Error("too large"); }) });
  const picker = dom.set("[data-profile-file]", element("input", { files: [{ name: "big.json", size: 2, arrayBuffer: async () => new TextEncoder().encode("{}").buffer }] }));
  createProfileActions(d).bindPage();
  await picker.fire("change");
  await settle();
  assert.match(lastLog().message, /too large/u);
  assert.equal(d.renderPage.count(), 1);
});

test("Update All updates subscriptions, skips local profiles and counts every outcome", async () => {
  state.profiles.push({ id: "broken", name: "Broken", active: false, sourceKind: "subscription", updated: "now" },
    { id: "kept", name: "Kept", active: false, sourceKind: "subscription", updated: "now" });
  const d = actionDeps({
    resolveProfileSource: spy(async (id) => (id === "home" ? null : `https://example.test/${id}`)),
    invokeProfileChange: spy(async (_command, { id }) => {
      if (id === "broken") throw new Error("HTTP 500");
      if (id === "kept") return { credential_cleanup_pending: true, credential_cleanup_error: "vault busy" };
      return {};
    }),
  });
  await createProfileActions(d).actions["update-all-profiles"]();
  assert.deepEqual(d.invokeProfileChange.calls.map(([, args]) => args.id), ["work", "broken", "kept"]);
  assert.ok(messages().includes("Update failed for Broken: HTTP 500"));
  assert.ok(messages().some((message) => /Kept updated\. Old credentials are retained for recovery\. Cleanup: vault busy/u.test(message)));
  assert.equal(lastLog().level, "error");
  assert.equal(lastLog().message, "Update All completed: 2 updated, 1 failed, 1 cleanup pending, 1 without a subscription URL");

  const clean = actionDeps({ resolveProfileSource: spy(async () => "https://example.test/x"), invokeProfileChange: spy(async () => ({})) });
  state.profiles = state.profiles.slice(0, 1);
  await createProfileActions(clean).actions["update-all-profiles"]();
  assert.equal(lastLog().level, "info");
  assert.equal(lastLog().message, "Update All completed: 1 updated");
});

test("the inspector saves its JSON, updates from its subscription and closes", async () => {
  const d = actionDeps();
  const { actions } = createProfileActions(d);
  await actions["save-profile-editor"]();
  assert.match(lastLog().message, /No profile editor is open/u);
  await actions["update-profile-from-inspector"]();
  assert.match(lastLog().message, /No profile is open/u);

  host.respond("read_profile_text", ({ id }) => ({ id, name: "New", body: "{}", digest: "d2" }));
  state.profileInspector = { id: "work", mode: "edit", profile: { id: "work", digest: "d1" } };
  dom.set("[data-profile-editor]", element("textarea", { value: "{\"outbounds\":[]}" }));
  await actions["save-profile-editor"]();
  assert.deepEqual(d.invokeProfileChange.calls[0], ["save_profile_text", { id: "work", expectedDigest: "d1", body: "{\"outbounds\":[]}" }]);
  assert.equal(state.profileInspector.profile.digest, "d2");
  assert.deepEqual(d.openCredentialSetup.calls, [["new"]]);

  state.profileInspector = { id: "work", mode: "qrcode" };
  await actions["update-profile-from-inspector"]();
  assert.deepEqual(d.runProfileMenuAction.calls, [["update", "work"]]);
  assert.equal(state.profileInspector.mode, "edit");

  await actions["close-profile-inspector"]();
  assert.equal(state.profileInspector, null);
});

test("a profile card selects on click, opens its menu on right click and ignores its own buttons", async () => {
  const d = actionDeps({ selectProfileById: spy(async () => { throw new Error("already logged"); }) });
  const card = element("article", { dataset: { profileCard: "work" } });
  const empty = element("article", { dataset: {} });
  dom.setAll("[data-profile-card]", [card, empty]);
  createProfileActions(d).bindPage();
  await card.fire("click", { target: element("button", { closestMap: { "button, a, input, textarea, select": card } }) });
  assert.equal(d.selectProfileById.count(), 0);
  await card.fire("click", { target: element("i") });
  assert.deepEqual(d.selectProfileById.calls, [["work"]]);
  assert.equal(d.renderPage.count(), 1, "a refused selection still renders");
  await empty.fire("click", { target: element("i") });
  assert.equal(d.selectProfileById.count(), 1, "a card without an id selects nothing");
  const event = await card.fire("contextmenu", { clientX: 30, clientY: 40 });
  assert.equal(event.defaultPrevented, true);
  assert.deepEqual(d.openProfileContextMenu.calls, [["work", 30, 40]]);
});

test("a profile's edit button opens the inspector and reports a failed read", async () => {
  const d = actionDeps();
  const edit = element("button", { dataset: { profileAction: "edit", profileId: "work" } });
  dom.setAll("[data-profile-action]", [edit]);
  createProfileActions(d).bindPage();
  host.respond("read_profile_text", { id: "work", name: "Work", body: "{}" });
  await edit.fire("click");
  assert.equal(state.profileInspector.mode, "edit");
  assert.equal(lastLog().message, "edit opened for work");
  host.respond("read_profile_text", new Error("gone"));
  await edit.fire("click");
  assert.equal(lastLog().message, "edit failed for work: gone");
  assert.equal(d.renderPage.count(), 2);
});

test("an invalid profile offers deletion and its subscription URL, and rejects anything else", async () => {
  state.invalidProfiles = [{ id: "bad", name: "Bad", selected: false, error: "x", sourceKind: "subscription", updated: "now" }];
  const d = actionDeps({ showInvalidProfileSource: spy(async () => { throw new Error("unreadable"); }) });
  const remove = element("button", { dataset: { invalidProfileAction: "delete", profileId: "bad" } });
  const source = element("button", { dataset: { invalidProfileAction: "show-source-url", profileId: "bad" } });
  const ghost = element("button", { dataset: { invalidProfileAction: "show-source-url", profileId: "ghost" } });
  const odd = element("button", { dataset: { invalidProfileAction: "explode", profileId: "bad" } });
  dom.setAll("[data-invalid-profile-action]", [remove, source, ghost, odd]);
  createProfileActions(d).bindPage();
  const event = await remove.fire("click");
  assert.equal(event.propagationStopped, true);
  assert.deepEqual(state.glassDialog, { kind: "delete-invalid", id: "bad" });
  assert.equal(d.renderGlassOverlays.count(), 1);
  await source.fire("click");
  assert.equal(lastLog().message, "Could not read the subscription URL of Bad: unreadable");
  await ghost.fire("click");
  assert.equal(lastLog().message, "Could not read the subscription URL of ghost: unreadable");
  await odd.fire("click");
  assert.equal(lastLog().message, "unknown profile menu action: explode");
});

test("a dropped profile is imported, set up and rendered, or its failure reported", async () => {
  const d = actionDeps();
  const { importProfileFromPath } = createProfileActions(d);
  await importProfileFromPath("/tmp/node.yaml");
  assert.deepEqual(d.invokeProfileChange.calls[0], ["import_profile_file", { path: "/tmp/node.yaml", name: null, activate: true }]);
  assert.deepEqual(d.openCredentialSetup.calls, [["new"]]);
  assert.equal(d.scheduleRender.count(), 1);
  d.invokeProfileChange = spy(async () => { throw new Error("not a profile"); });
  await createProfileActions(d).importProfileFromPath("/tmp/x");
  assert.equal(lastLog().message, "Drag-drop import failed: not a profile");
});

test("the inspector opens a profile, renders a QR code or states why there is none", async () => {
  host.respond("read_profile_text", { id: "work", name: "Work", body: "{}" });
  host.respond("profile_qrcode_svg", "<svg id=\"qr\"/>");
  await openProfileInspector("work", "qrcode");
  assert.equal(state.profileInspector.svg, "<svg id=\"qr\"/>");
  host.respond("profile_qrcode_svg", new Error("local profile"));
  await openProfileInspector("work", "qrcode");
  assert.equal(state.profileInspector.error, "local profile");
  assert.equal(lastLog().message, "Could not render the profile QR code: local profile");
  await openProfileInspector("work", "inspect", "route");
  assert.deepEqual(state.profileInspector, { id: "work", mode: "inspect", profile: { id: "work", name: "Work", body: "{}" }, focusKey: "route" });
});

test("the editor focuses the section a menu item named", () => {
  focusProfileEditorSection(null);
  dom.set("[data-profile-editor]", element("div"));
  focusProfileEditorSection("route");
  const editor = Object.setPrototypeOf(element("textarea", {
    value: "{\n  \"log\": {},\n  \"route\": {\n  }\n}",
  }), HTMLTextAreaElement.prototype);
  dom.set("[data-profile-editor]", editor);
  focusProfileEditorSection("missing");
  assert.equal(editor.focused, false);
  focusProfileEditorSection("route");
  assert.equal(editor.focused, true);
  assert.deepEqual(editor.selection, [17, 25], "the section key is selected");
  assert.equal(editor.scrollTop, 0, "an early section needs no scrolling");
  editor.value = `${"\n".repeat(10)}"route": {}`;
  focusProfileEditorSection("route");
  assert.equal(editor.scrollTop, 10 * 18 - 40);
});

test("the inspector panel shows the editor, a QR code or the profile's identity", () => {
  state.profiles = [];
  state.profileInspector = { id: "work", mode: "edit", profile: { id: "work", name: "Work", body: "{\"a\":1}", bytes: 1024, active: true, source_url: "https://example.test/sub" } };
  let html = renderProfiles();
  assert.match(html, /Work · edit/u);
  assert.match(html, /data-profile-editor[^>]*>\{&quot;a&quot;:1\}<\/textarea>/u);
  assert.match(html, /<dd>1\.0 KB<\/dd>/u);
  assert.match(html, /<dd>yes<\/dd>/u);
  assert.match(html, /data-action="update-profile-from-inspector"/u);
  state.profileInspector.profile = { id: "work", body: "{}" };
  html = renderProfiles();
  assert.doesNotMatch(html, /update-profile-from-inspector/u, "a local profile has no subscription to update from");
  assert.match(html, /work · edit/u, "the id names a profile without a name");
  assert.match(html, /<dd>local file<\/dd>/u);

  state.profileInspector = { id: "work", mode: "qrcode", svg: "<svg id=\"qr\"/>", profile: { sourceUrl: "https://example.test/sub" } };
  html = renderProfiles();
  assert.match(html, /<div class="profile-qr"><svg id="qr"\/><\/div><p class="muted">https:\/\/example.test\/sub<\/p>/u);
  state.profileInspector = { id: "work", mode: "qrcode", error: "no URL" };
  assert.match(renderProfiles(), /<p class="empty">no URL<\/p>/u);
  state.profileInspector = { id: "work", mode: "qrcode" };
  assert.match(renderProfiles(), /has no subscription URL/u);
  state.profileInspector = { id: "work", mode: "inspect" };
  html = renderProfiles();
  assert.match(html, /<dt>ID<\/dt><dd>work<\/dd>/u);
  assert.match(html, /<dd>no<\/dd>/u);
});

function dataDeps(overrides = {}) {
  return {
    cancelDelayTest: spy(),
    loadProvidersSnapshot: spy(async () => undefined),
    providerSelectionChanged: spy(),
    loadEngineStatus: spy(async () => true),
    loadRuntimeProjection: spy(async () => true),
    ...overrides,
  };
}

test("a profile's subscription URL is read once, and a failed read is reported and remembered", async () => {
  const data = createProfileData(dataDeps());
  assert.equal(await data.resolveProfileSource("missing"), undefined);
  host.respond("read_profile_text", { id: "work", source_url: "https://example.test/sub" });
  assert.equal(await data.resolveProfileSource("work"), "https://example.test/sub");
  assert.equal(await data.resolveProfileSource("work"), "https://example.test/sub");
  assert.equal(host.argsOf("read_profile_text").length, 1, "the URL is read only once");
  host.respond("read_profile_text", new Error("locked"));
  assert.equal(await data.resolveProfileSource("home"), undefined);
  assert.equal(state.profiles[1].sourceError, "locked");
  assert.equal(lastLog().message, "Could not read Home source metadata: locked");
});

test("applying the selected profile says whether the engine restarted or only staged it", async () => {
  const d = dataDeps();
  const data = createProfileData(d);
  host.respond("apply_active_profile", { name: "Work", applied: true, bytes: 4096 });
  await data.applyActiveProfile("migrating Work");
  assert.equal(lastLog().message, "Work: projection applied and engine restarted (4.0 KB) after migrating Work");
  host.respond("apply_active_profile", { name: "Work", applied: false });
  const applied = await data.applyActiveProfile();
  assert.equal(applied.applied, false);
  assert.equal(lastLog().message, "Work: projection validated and staged (engine is off) (0 B)");
  assert.equal(d.loadRuntimeProjection.count(), 2);
});

test("a profile change reports reset groups and always re-reads profiles, engine, controller and projection", async () => {
  const d = dataDeps();
  const data = createProfileData(d);
  host.respond("profiles_snapshot", { profiles: [], invalid_profiles: [] });
  host.respond("select_profile", { reset_proxy_groups: ["Proxy", "Auto"] });
  state.engine = { ...state.engine, active: true };
  host.respond("controller_snapshot", null);
  await data.invokeProfileChange("select_profile", { id: "work" });
  assert.ok(messages().includes("Saved nodes were removed from these groups; the new defaults apply: Proxy, Auto"));
  assert.equal(d.loadEngineStatus.count(), 1);
  assert.equal(d.loadRuntimeProjection.count(), 1);
  host.respond("select_profile", new Error("refused"));
  await assert.rejects(() => data.invokeProfileChange("select_profile", { id: "work" }), /refused/u);
  assert.equal(d.loadRuntimeProjection.count(), 2, "a refused change still re-reads every view of it");
});

test("selecting the active profile is a no-op and an unknown profile is an error", async () => {
  const data = createProfileData(dataDeps());
  assert.equal(await data.selectProfileById("home"), false);
  assert.equal(lastLog().message, "Home is already active");
  await assert.rejects(() => data.selectProfileById("ghost"), /profile not found: ghost/u);
});

test("credential setup for a profile that disappeared is closed", async () => {
  const d = dataDeps();
  const data = createProfileData(d);
  state.credentialSetup = { profileId: "gone" };
  host.respond("profiles_snapshot", { profiles: [{ id: "work", name: "Work", source_kind: "local", active: false }], invalid_profiles: [] });
  assert.equal(await data.loadProfilesSnapshot(), true);
  assert.equal(state.credentialSetup, null);
  state.credentialSetup = { profileId: "work" };
  await data.loadProfilesSnapshot();
  assert.deepEqual(state.credentialSetup, { profileId: "work" }, "setup for a listed profile stays");
  assert.equal(runtime.savedProfilePolicyEpoch > 0, true);
});

function dialogDeps(overrides = {}) {
  return {
    renderPage: spy(),
    renderGlassOverlays: spy(),
    closeGlassOverlays: spy(),
    closeGlassDialog: spy(),
    loadProfilesSnapshot: spy(async () => true),
    invokeProfileChange: spy(async () => ({ name: "Work copy" })),
    ...overrides,
  };
}

test("copying a profile needs a name and imports the original's text under it", async () => {
  const d = dialogDeps();
  const dialogs = createProfileDialogs(d);
  const confirm = element("button", { dataset: { glassCopyConfirm: "work" } });
  dom.setAll("[data-glass-copy-confirm]", [confirm]);
  dialogs.dialogs.bind();
  dom.set("[data-glass-copy-name]", element("input", { value: "   " }));
  await confirm.fire("click");
  assert.equal(host.calls.length, 0, "an empty name copies nothing");
  dom.set("[data-glass-copy-name]", element("input", { value: " Work copy " }));
  host.respond("read_profile_text", { id: "work", body: "{\"x\":1}" });
  await confirm.fire("click");
  assert.deepEqual(d.invokeProfileChange.calls, [["import_profile_text", { name: "Work copy", body: "{\"x\":1}" }]]);
  assert.equal(d.closeGlassOverlays.count(), 1);
  assert.equal(lastLog().message, "Copied profile to Work copy; select it to make it active");
  host.respond("read_profile_text", new Error("locked"));
  await confirm.fire("click");
  assert.equal(lastLog().message, "Copy failed: locked");
  assert.equal(d.renderPage.count(), 2);
});

test("editing a profile's name and URL saves both and reports a refusal", async () => {
  const d = dialogDeps();
  const confirm = element("button", { dataset: { glassSettingsConfirm: "work" } });
  dom.setAll("[data-glass-settings-confirm]", [confirm]);
  createProfileDialogs(d).dialogs.bind();
  host.respond("update_profile_info", null);
  await confirm.fire("click");
  assert.deepEqual(host.argsOf("update_profile_info"), [{ id: "work", name: "", url: "" }], "missing fields are sent empty");
  dom.set("[data-glass-settings-name]", element("input", { value: " Office " }));
  dom.set("[data-glass-settings-url]", element("input", { value: " https://example.test/o " }));
  await confirm.fire("click");
  assert.deepEqual(host.argsOf("update_profile_info")[1], { id: "work", name: "Office", url: "https://example.test/o" });
  assert.equal(lastLog().message, "Profile settings saved: Office");
  host.respond("update_profile_info", new Error("invalid URL"));
  await confirm.fire("click");
  assert.equal(lastLog().message, "Settings failed: invalid URL");
  assert.equal(d.closeGlassOverlays.count(), 2);
});

test("the delete button confirms the deletion of the profile it names", async () => {
  const d = dialogDeps();
  const confirm = element("button", { dataset: { glassDeleteConfirm: "work" } });
  dom.setAll("[data-glass-delete-confirm]", [confirm]);
  createProfileDialogs(d).dialogs.bind();
  state.glassDialog = { kind: "delete", id: "work" };
  host.respond("delete_profile", true);
  const event = await confirm.fire("click");
  assert.equal(event.defaultPrevented, true);
  assert.deepEqual(host.argsOf("delete_profile"), [{ id: "work" }]);
  assert.deepEqual(d.closeGlassDialog.calls, [[{ kind: "delete", id: "work" }]]);
});
