// A dialog that opens at once keeps what is typed in it when the page draws it
// again, as every render of the page does while it is open: a read that ends
// with nothing to open, a change of the engine. The DNS query and the copy and
// the information of a profile keep it in their state. The secrets of the
// credential dialog are kept out of the state and of the markup: the module of
// that dialog keeps them for the dialog they were typed in, puts them back
// into the fields it draws, and lets them go once the vault has had them.
import { dom, element, host, settle, spy } from "./support/fake-host.mjs";
import { stopEngine } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { inspect } from "node:util";
import { state } from "../src/state.js";
import { createCredentialSetup } from "../src/credential-setup.js";
import { createDiagnosticsDialogs } from "../src/diagnostics-dialogs.js";
import { createProfileDialogs } from "../src/profile-dialogs.js";

const PROFILE = Object.freeze({ id: "work", name: "Work", sourceUrl: "https://subscription.example/work" });
const REFERENCES = Object.freeze([
  { id: "34db18b6-9903-4e9f-8854-15648e19e4f3", kind: "trojan_password" },
  { id: "5d1f4e9c-1c1a-4a2b-8f3d-2b6f9c0a7e11", kind: "vmess_uuid" },
]);
const page = () => ({ renderPage: spy(), renderGlassOverlays: spy(), closeGlassOverlays: spy() });

/// Draws the open dialog as the overlay layer does: its markup, then fields
/// that the markup has for `selectors`, new ones each time, bound by its
/// provider. The fields are found by their selector.
function draw(provider, selectors, profile = null) {
  const markup = provider.render(state.glassDialog, profile);
  const fields = Object.fromEntries(selectors.map((selector) => [selector, dom.setAll(selector, [element("input")])[0]]));
  provider.bind();
  return { markup, fields };
}

async function type(field, text) {
  field.value = text;
  await field.fire("input");
}

/// Draws the dialog of credentials as the overlay layer does, with a field for
/// each of two references, new ones each time.
function drawCredentials(credentials) {
  const markup = credentials.dialogs.render(state.glassDialog);
  const secrets = dom.setAll("[data-credential-secret]",
    ["0", "1"].map((credentialIndex) => element("input", { dataset: { credentialIndex } })));
  credentials.dialogs.bind();
  return { markup, secrets, values: () => secrets.map((field) => field.value) };
}

beforeEach(() => {
  host.reset();
  dom.reset();
  state.logs = [];
  state.glassDialog = null;
  state.credentialSetup = null;
  stopEngine();
});

test("the DNS query keeps the name and the type typed in it", async () => {
  const diagnostics = createDiagnosticsDialogs({ ...page(), runtimeProjectionActionAllowed: () => true });
  const SELECTORS = ["[data-glass-dns-name]", "[data-glass-dns-type]"];
  await diagnostics.actions["dns-query"]();
  const opened = state.glassDialog;
  let drawn = draw(diagnostics.dialogs, SELECTORS);
  assert.match(drawn.markup, /data-glass-dns-name value="www\.gstatic\.com"/u);
  await type(drawn.fields["[data-glass-dns-name]"], "example.test");
  await type(drawn.fields["[data-glass-dns-type]"], "AAAA");
  drawn = draw(diagnostics.dialogs, SELECTORS);
  assert.match(drawn.markup, /data-glass-dns-name value="example\.test"/u);
  assert.match(drawn.markup, /data-glass-dns-type value="AAAA"/u);
  assert.equal(state.glassDialog, opened, "it is the dialog that opened");
});

test("the copy of a profile and its information keep what is typed in them", async () => {
  const profiles = createProfileDialogs({ ...page(), closeGlassDialog: spy(), loadProfilesSnapshot: spy(async () => true),
    invokeProfileChange: spy(), forgetProfileSource: spy() });
  state.glassDialog = { kind: "copy", id: PROFILE.id };
  let drawn = draw(profiles.dialogs, ["[data-glass-copy-name]"], PROFILE);
  assert.match(drawn.markup, /data-glass-copy-name value="Work copy"/u);
  await type(drawn.fields["[data-glass-copy-name]"], "Holiday");
  drawn = draw(profiles.dialogs, ["[data-glass-copy-name]"], PROFILE);
  assert.match(drawn.markup, /data-glass-copy-name value="Holiday"/u);

  const SETTINGS = ["[data-glass-settings-name]", "[data-glass-settings-url]"];
  state.glassDialog = { kind: "settings", id: PROFILE.id };
  drawn = draw(profiles.dialogs, SETTINGS, PROFILE);
  assert.match(drawn.markup, /data-glass-settings-name value="Work"/u);
  assert.match(drawn.markup, /data-glass-settings-url value="https:\/\/subscription\.example\/work"/u);
  await type(drawn.fields["[data-glass-settings-name]"], "Home");
  await type(drawn.fields["[data-glass-settings-url]"], "https://subscription.example/home");
  drawn = draw(profiles.dialogs, SETTINGS, PROFILE);
  assert.match(drawn.markup, /data-glass-settings-name value="Home"/u);
  assert.match(drawn.markup, /data-glass-settings-url value="https:\/\/subscription\.example\/home"/u);
  // An empty field is what was typed as well.
  await type(drawn.fields["[data-glass-settings-url]"], "");
  drawn = draw(profiles.dialogs, SETTINGS, PROFILE);
  assert.match(drawn.markup, /data-glass-settings-url value="" /u);
});

test("the credential dialog puts the secrets typed in it back into the fields it draws, and never into its markup", async () => {
  const credentials = createCredentialSetup(page());
  const drawAgain = () => drawCredentials(credentials);
  state.credentialSetup = { profileId: "work", profileName: "Work", requiredCount: 2, presentCount: 0, missing: [...REFERENCES], vaultAvailable: true, error: null };
  const opened = { kind: "credentials", id: "work" };
  state.glassDialog = opened;
  let drawn = drawAgain();
  assert.deepEqual(drawn.values(), ["", ""]);
  await type(drawn.secrets[1], "s3cret");
  await type(drawn.secrets[0], "hunter2");
  drawn = drawAgain();
  assert.deepEqual(drawn.values(), ["hunter2", "s3cret"], "the page drew the dialog again");
  assert.doesNotMatch(drawn.markup, /hunter2|s3cret/u);
  assert.doesNotMatch(inspect(state, { depth: Infinity }), /hunter2|s3cret/u, "the state holds no secret");
  // The overlays drawn without their dialog, closed or replaced by another
  // dialog of credentials or of anything else, let them go.
  for (const instead of [null, { kind: "credentials", id: "work" }, { kind: "info", payload: { title: "Allow LAN", body: "" } }]) {
    state.glassDialog = instead;
    credentials.dialogs.bind();
    state.glassDialog = opened;
    assert.deepEqual(drawAgain().values(), ["", ""], `let go for ${instead?.kind ?? "no dialog"}`);
    drawn = drawAgain();
    await type(drawn.secrets[0], "hunter2");
    await type(drawn.secrets[1], "s3cret");
  }
  drawn = drawAgain();
  assert.deepEqual(drawn.values(), ["hunter2", "s3cret"]);

  // The vault refuses them: they leave the fields and the dialog all the same.
  const confirm = element("button", { dataset: { glassCredentialsConfirm: "work" } });
  dom.setAll("[data-glass-credentials-confirm]", [confirm]);
  credentials.dialogs.bind();
  host.respond("provision_profile_credentials", new Error("the vault refuses"));
  await confirm.fire("click");
  assert.equal(host.argsOf("provision_profile_credentials").length, 1);
  assert.deepEqual(drawn.values(), ["", ""], "the fields are cleared");
  assert.equal(state.glassDialog, opened, "the dialog stays open");
  assert.deepEqual(drawAgain().values(), ["", ""], "nothing of them is drawn again");
});

test("a secret goes back only into the field of its own reference, of the profile of its dialog", async () => {
  const credentials = createCredentialSetup(page());
  const work = { profileId: "work", profileName: "Work", requiredCount: 2, presentCount: 0, missing: [...REFERENCES], vaultAvailable: true, error: null };
  state.glassDialog = { kind: "credentials", id: "work" };
  state.credentialSetup = work;
  let drawn = drawCredentials(credentials);
  await type(drawn.secrets[0], "hunter2");
  // The same references in the other order: the secret follows its reference.
  state.credentialSetup = { ...work, missing: [REFERENCES[1], REFERENCES[0]] };
  assert.deepEqual(drawCredentials(credentials).values(), ["", "hunter2"]);
  // What the dialog shows of another profile gets none of them and keeps nothing typed there.
  state.credentialSetup = { ...work, profileId: "home", profileName: "Home" };
  drawn = drawCredentials(credentials);
  assert.deepEqual(drawn.values(), ["", ""]);
  await type(drawn.secrets[1], "s3cret");
  state.credentialSetup = work;
  assert.deepEqual(drawCredentials(credentials).values(), ["hunter2", ""]);
});

test("a store of credentials that ends once another dialog of credentials was opened leaves what is typed there", async () => {
  const credentials = createCredentialSetup(page());
  state.credentialSetup = { profileId: "work", profileName: "Work", requiredCount: 2, presentCount: 0, missing: [...REFERENCES], vaultAvailable: true, error: null };
  state.glassDialog = { kind: "credentials", id: "work" };
  let drawn = drawCredentials(credentials);
  await type(drawn.secrets[0], "hunter2");
  await type(drawn.secrets[1], "hunter3");
  const confirm = element("button", { dataset: { glassCredentialsConfirm: "work" } });
  dom.setAll("[data-glass-credentials-confirm]", [confirm]);
  credentials.dialogs.bind();
  let refuse = null;
  host.respond("provision_profile_credentials", () => new Promise((_resolve, reject) => { refuse = reject; }));
  const stored = confirm.fire("click");
  await settle();
  // Its dialog is dismissed while the vault stores, and another is opened, with
  // a button of its own, and typed in.
  state.glassDialog = { kind: "credentials", id: "work" };
  dom.setAll("[data-glass-credentials-confirm]", [element("button", { dataset: { glassCredentialsConfirm: "work" } })]);
  drawn = drawCredentials(credentials);
  await type(drawn.secrets[1], "s3cret");
  refuse(new Error("the vault refuses"));
  await stored;
  assert.deepEqual(drawCredentials(credentials).values(), ["", "s3cret"]);
});
