// Profiles: source metadata, invalid stored profiles, Update All, credential
// cleanup, the configuration preview, and imports.
import assert from "node:assert/strict";
import test from "node:test";
import {
  OFF_ENGINE, PROFILE_ID, PROJECTION, RUNNING_ENGINE, appModule, element, emit, glassRoot,
  interactiveElement, invocationDetails, invoked, querySelectorAllElements, querySelectorElements,
  rejected, reloadButton, renderPage, responses, setEngine, state,
} from "./support/render-harness.mjs";
import { readStylesheet } from "./support/stylesheet.mjs";

test("runtime configuration preview is offline and depends only on repository-backed selection", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalProfiles = structuredClone(state.profiles);
  const originalProfilesUnavailableReason = state.profilesUnavailableReason;
  const originalDialog = state.glassDialog;

  try {
    state.profiles = [{
      id: PROFILE_ID,
      name: "Work",
      active: true,
      bytes: 2048,
      updatedEpochSecs: null,
      updated: "now",
      sourceKind: "local",
    }];
    state.profilesUnavailableReason = null;
    await setEngine(OFF_ENGINE);
    state.glassDialog = null;
    invoked.length = 0;
    invocationDetails.length = 0;

    await appModule.handleAction("preview-runtime-config");

    assert.equal(invoked.filter((command) => command === "read_runtime_config_text").length, 1);
    assert.equal(state.glassDialog?.kind, "preview-config");
    assert.equal(state.glassDialog?.payload, PROJECTION);

    state.glassDialog = null;
    state.profilesUnavailableReason = "profile repository unavailable";
    await appModule.handleAction("preview-runtime-config");
    assert.equal(invoked.filter((command) => command === "read_runtime_config_text").length, 1);
    assert.equal(state.glassDialog, null);

    state.profilesUnavailableReason = null;
    state.profiles = [];
    await appModule.handleAction("preview-runtime-config");
    assert.equal(invoked.filter((command) => command === "read_runtime_config_text").length, 1);
    assert.equal(state.glassDialog, null);
  } finally {
    state.profiles = originalProfiles;
    state.profilesUnavailableReason = originalProfilesUnavailableReason;
    state.glassDialog = originalDialog;
    responses.engine_snapshot = originalEngine;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("profile cards show source type on first load without fetching URLs or inventing quota", async () => {
  const originalProfiles = responses.profiles_snapshot;
  try {
    responses.profiles_snapshot = { profiles: [
      { ...originalProfiles.profiles[0], name: "本地-示例-09.18", source_kind: "local" },
      { ...originalProfiles.profiles[0], id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name: "Remote", source_kind: "subscription", active: false },
    ], invalid_profiles: [] };
    state.profiles = [];
    const before = invocationDetails.length;
    await reloadButton.click();
    const html = await renderPage("profiles");
    assert.match(html, /本地-示例-09\.18/u);
    assert.match(html, /local file \(/u);
    assert.match(html, /subscription \(/u);
    assert.match(html, /aria-current="true"/u);
    assert.match(html, /Clash YAML imports nodes, groups, supported routing rules, DNS, and hosts/u);
    assert.match(html, /Unsupported policies are reported before saving/u);
    assert.doesNotMatch(html, /source not listed|quota not reported|profile-usage|2 KB/u);
    assert.equal(invocationDetails.slice(before).some(({ command }) => command === "profile_text"), false);
    state.profiles[0].sourceUrl = "https://private.example/?token=private-test-value";
    const afterDetails = await renderPage("profiles");
    assert.match(afterDetails, /local file \(/u, "cached URL metadata does not determine the card's source type");
    assert.doesNotMatch(afterDetails, /private\.example|private-test-value/u);
  } finally {
    responses.profiles_snapshot = originalProfiles;
    state.profiles = [];
    await reloadButton.click();
  }
});

test("missing or unknown profile source metadata is surfaced as a repository error", async () => {
  const originalProfiles = responses.profiles_snapshot;
  try {
    for (const sourceKind of [undefined, "unsupported"]) {
      responses.profiles_snapshot = { profiles: [{ ...originalProfiles.profiles[0], source_kind: sourceKind }], invalid_profiles: [] };
      await reloadButton.click();
      const html = await renderPage("profiles");
      assert.match(html, /profile snapshot has an invalid source kind/u);
      assert.doesNotMatch(html, /data-profile-card=/u);
    }
  } finally {
    responses.profiles_snapshot = originalProfiles;
    await reloadButton.click();
  }
});

const INVALID_PROFILE_ID = "3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d";

const INVALID_PROFILE_REASON = "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS";

const INVALID_PROFILE_URL = "https://subscription.example/profile?token=private-test-value";

const invalidProfileRecord = (selected) => ({
  id: INVALID_PROFILE_ID,
  name: "Reality node",
  selected,
  updated_epoch_secs: 1,
  source_kind: "subscription",
  error: INVALID_PROFILE_REASON,
});

const loggedCount = (message) => state.logs.filter((entry) => entry.message === message).length;

test("an invalid stored profile is listed with its reason and offers only deletion and its subscription URL", async () => {
  const originalProfiles = responses.profiles_snapshot;
  const originalWrite = navigator.clipboard.writeText;
  const copied = [];
  const show = interactiveElement();
  show.dataset.invalidProfileAction = "show-source-url";
  show.dataset.profileId = INVALID_PROFILE_ID;
  const remove = interactiveElement();
  remove.dataset.invalidProfileAction = "delete";
  remove.dataset.profileId = INVALID_PROFILE_ID;
  const unknown = interactiveElement();
  unknown.dataset.invalidProfileAction = "edit";
  unknown.dataset.profileId = INVALID_PROFILE_ID;
  const copy = interactiveElement();
  const confirmDelete = interactiveElement();
  confirmDelete.dataset.glassDeleteConfirm = INVALID_PROFILE_ID;
  try {
    navigator.clipboard.writeText = async (value) => { copied.push(value); };
    responses.profiles_snapshot = {
      profiles: [{ ...originalProfiles.profiles[0], active: false }],
      invalid_profiles: [invalidProfileRecord(true)],
    };
    responses.read_profile_source_url = INVALID_PROFILE_URL;
    await reloadButton.click();
    const html = await renderPage("profiles");
    assert.ok(html.includes(`data-invalid-profile-card="${INVALID_PROFILE_ID}" aria-current="true"`), "the selected invalid profile is marked selected");
    assert.ok(html.includes(`Selected, but invalid: ${INVALID_PROFILE_REASON}`));
    assert.ok(!html.includes(`data-profile-card="${INVALID_PROFILE_ID}"`), "an invalid profile is never a selectable card");
    assert.match(html, /data-invalid-profile-action="show-source-url"/u);
    assert.match(html, /data-invalid-profile-action="delete"/u);
    assert.doesNotMatch(html, /subscription\.example|private-test-value/u);
    assert.equal(state.profiles.some((profile) => profile.active), false, "no valid profile stands in for the invalid selection");

    querySelectorAllElements.set("[data-invalid-profile-action]", [show, remove, unknown]);
    querySelectorAllElements.set("[data-glass-delete-confirm]", [confirmDelete]);
    querySelectorAllElements.set("[data-glass-copy-text]", [copy]);
    await renderPage("profiles");
    invocationDetails.length = 0;
    await unknown.trigger("click");
    assert.deepEqual(invocationDetails, [], "an unknown card action reads nothing");
    assert.equal(loggedCount("unknown profile menu action: edit"), 1);

    await show.trigger("click");
    assert.deepEqual(invocationDetails.map(({ command }) => command), ["read_profile_source_url"]);
    assert.deepEqual(invocationDetails[0].args, { id: INVALID_PROFILE_ID });
    assert.deepEqual(state.glassDialog, { kind: "invalid-profile-source", id: INVALID_PROFILE_ID, payload: INVALID_PROFILE_URL });
    assert.ok(glassRoot.innerHTML.includes(INVALID_PROFILE_URL));
    assert.match(glassRoot.innerHTML, /Import this URL again to replace “Reality node”, then delete the invalid profile\./u);
    assert.deepEqual(copied, [], "nothing reaches the clipboard before the user copies");
    await copy.trigger("click");
    assert.deepEqual(copied, [INVALID_PROFILE_URL]);
    assert.equal(state.logs.some((entry) => entry.message.includes("private-test-value")), false);

    state.glassDialog = null;
    responses.read_profile_source_url = null;
    await show.trigger("click");
    assert.equal(state.glassDialog, null);
    assert.equal(loggedCount("Could not read the subscription URL of Reality node: Reality node has no subscription URL"), 1);

    await remove.trigger("click");
    assert.deepEqual(state.glassDialog, { kind: "delete-invalid", id: INVALID_PROFILE_ID });
    assert.match(glassRoot.innerHTML, /Delete “Reality node”\? It is selected but fails validation; afterwards no profile is selected\./u);
    rejected.delete_profile = `the selected profile "Reality node" (${INVALID_PROFILE_ID}) is invalid; stop the core, or select another profile, before deleting it`;
    invocationDetails.length = 0;
    await confirmDelete.trigger("click");
    assert.deepEqual(state.glassDialog, { kind: "delete-invalid", id: INVALID_PROFILE_ID }, "a refused deletion keeps its dialog");
    assert.equal(loggedCount(`Delete failed: ${rejected.delete_profile}`), 1);
    assert.ok(invocationDetails.some(({ command }) => command === "profiles_snapshot"), "a failed deletion re-reads the list");

    delete rejected.delete_profile;
    responses.delete_profile = true;
    responses.profiles_snapshot = { profiles: [{ ...originalProfiles.profiles[0], active: false }], invalid_profiles: [] };
    invocationDetails.length = 0;
    await confirmDelete.trigger("click");
    assert.deepEqual(invocationDetails.find(({ command }) => command === "delete_profile").args, { id: INVALID_PROFILE_ID });
    assert.equal(invocationDetails.some(({ command }) => command === "select_profile"), false, "deleting selects nothing else");
    assert.equal(state.glassDialog, null);
    assert.deepEqual(state.invalidProfiles, []);
    assert.equal(loggedCount("Profile deleted: Reality node"), 1);
  } finally {
    navigator.clipboard.writeText = originalWrite;
    delete rejected.delete_profile;
    delete responses.delete_profile;
    delete responses.read_profile_source_url;
    responses.profiles_snapshot = originalProfiles;
    querySelectorAllElements.clear();
    state.glassDialog = null;
    await reloadButton.click();
  }
});

test("an unselected invalid local profile shows its reason and has no subscription URL", async () => {
  const originalProfiles = responses.profiles_snapshot;
  try {
    responses.profiles_snapshot = {
      profiles: [],
      invalid_profiles: [{ ...invalidProfileRecord(false), source_kind: "local" }],
    };
    await reloadButton.click();
    const html = await renderPage("profiles");
    assert.ok(html.includes(`Invalid: ${INVALID_PROFILE_REASON}`));
    assert.doesNotMatch(html, /data-invalid-profile-action="show-source-url"/u);
    assert.match(html, /data-invalid-profile-action="delete"/u);
    assert.doesNotMatch(html, /No profiles found in the managed profiles directory/u, "an invalid profile is not an empty repository");
    assert.doesNotMatch(html, /aria-current="true"/u);
  } finally {
    responses.profiles_snapshot = originalProfiles;
    await reloadButton.click();
  }
});

test("the invalid profile dialogs render for the web page", async () => {
  const originalInvalid = state.invalidProfiles;
  try {
    state.invalidProfiles = [{ id: INVALID_PROFILE_ID, name: "Reality node", selected: false, updated: "now", sourceKind: "subscription", error: INVALID_PROFILE_REASON }];
    for (const [dialog, needle] of [
      [{ kind: "delete-invalid", id: INVALID_PROFILE_ID }, "Delete “Reality node”? It fails validation and cannot be used."],
      [{ kind: "invalid-profile-source", id: INVALID_PROFILE_ID, payload: INVALID_PROFILE_URL }, INVALID_PROFILE_URL],
      // A valid-profile dialog never opens for an invalid entry.
      [{ kind: "settings", id: INVALID_PROFILE_ID }, null],
    ]) {
      state.glassDialog = dialog;
      glassRoot.innerHTML = "";
      await renderPage("profiles");
      if (needle) assert.ok(glassRoot.innerHTML.includes(needle), `${dialog.kind}: ${glassRoot.innerHTML}`);
      else assert.doesNotMatch(glassRoot.innerHTML, /Edit profile information/u);
    }
  } finally {
    state.invalidProfiles = originalInvalid;
    state.glassDialog = null;
  }
});

test("a malformed profile snapshot or invalid entry is surfaced as a repository error", async () => {
  const originalProfiles = responses.profiles_snapshot;
  try {
    for (const [snapshot, message] of [
      [originalProfiles.profiles, "profile snapshot is malformed"],
      [{ profiles: originalProfiles.profiles }, "profile snapshot is malformed"],
      [{ ...originalProfiles, invalid_profiles: [{ ...invalidProfileRecord(false), error: "" }] }, "an invalid profile in the snapshot has no validation error"],
      [{ ...originalProfiles, invalid_profiles: [{ ...invalidProfileRecord(false), selected: undefined }] }, "an invalid profile in the snapshot has no validation error"],
      [{ ...originalProfiles, invalid_profiles: [{ ...invalidProfileRecord(false), source_kind: "unsupported" }] }, "profile snapshot has an invalid source kind"],
    ]) {
      responses.profiles_snapshot = { ...originalProfiles, invalid_profiles: [invalidProfileRecord(false)] };
      await reloadButton.click();
      assert.equal(state.invalidProfiles.length, 1);
      responses.profiles_snapshot = snapshot;
      await reloadButton.click();
      const html = await renderPage("profiles");
      assert.ok(html.includes(message), message);
      assert.doesNotMatch(html, /data-profile-card=|data-invalid-profile-card=/u);
      assert.deepEqual(state.invalidProfiles, []);
    }
  } finally {
    responses.profiles_snapshot = originalProfiles;
    await reloadButton.click();
  }
});

test("Update All never reads or updates an invalid profile", async () => {
  const originalProfiles = responses.profiles_snapshot;
  const remoteId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  try {
    responses.profiles_snapshot = {
      profiles: [{ ...originalProfiles.profiles[0], id: remoteId, name: "Remote", source_kind: "subscription", active: true }],
      invalid_profiles: [invalidProfileRecord(false)],
    };
    responses.read_profile_text = (args) => {
      if (args.id !== remoteId) throw new Error(`unexpected read of ${args.id}`);
      return { source_url: "https://subscription.example/remote" };
    };
    responses.update_profile = { name: "Remote", credential_cleanup_pending: false };
    state.profiles = [];
    await reloadButton.click();
    invocationDetails.length = 0;
    await appModule.handleAction("update-all-profiles");
    assert.equal(invocationDetails.some(({ args }) => args?.id === INVALID_PROFILE_ID), false);
    assert.deepEqual(invocationDetails.filter(({ command }) => command === "update_profile").map(({ args }) => args), [{ id: remoteId }]);
    assert.equal(loggedCount("Update All completed: 1 updated"), 1);
  } finally {
    delete responses.read_profile_text;
    delete responses.update_profile;
    responses.profiles_snapshot = originalProfiles;
    state.profiles = [];
    await reloadButton.click();
  }
});

test("a credential cleanup refusal is shown where cleanup was asked for", async () => {
  const refusal = `credential cleanup needs every stored profile to pass validation; delete the invalid profiles first: "Reality node" (${INVALID_PROFILE_ID})`;
  try {
    rejected.preview_credential_gc = refusal;
    await appModule.handleAction("preview-credential-gc");
    assert.equal(state.glassDialog?.kind, "info");
    assert.equal(state.credentialGcPreview, null);
    await renderPage("settings");
    assert.ok(glassRoot.innerHTML.includes(`Credential cleanup is unavailable: ${refusal}`.replaceAll('"', "&quot;")), glassRoot.innerHTML);
    assert.equal(loggedCount(refusal), 1);
  } finally {
    delete rejected.preview_credential_gc;
    state.glassDialog = null;
  }
});

test("a selected invalid profile blocks the configuration preview with its reason", async () => {
  const originalProfiles = structuredClone(state.profiles);
  const originalInvalid = structuredClone(state.invalidProfiles);
  try {
    state.profiles = [{ id: PROFILE_ID, name: "Work", active: false, bytes: 2048, updatedEpochSecs: null, updated: "now", sourceKind: "local" }];
    state.invalidProfiles = [{ id: INVALID_PROFILE_ID, name: "Reality node", selected: true, updated: "now", sourceKind: "subscription", error: INVALID_PROFILE_REASON }];
    state.profilesUnavailableReason = null;
    state.glassDialog = null;
    invoked.length = 0;
    await appModule.handleAction("preview-runtime-config");
    assert.equal(invoked.includes("read_runtime_config_text"), false);
    assert.equal(state.glassDialog, null);
    const message = `Configuration preview is unavailable: the selected profile “Reality node” is invalid: ${INVALID_PROFILE_REASON}`;
    assert.equal(loggedCount(message), 1);
  } finally {
    state.profiles = originalProfiles;
    state.invalidProfiles = originalInvalid;
  }
});

test("ordinary profile operations remain available while the core is running", async () => {
  await setEngine(OFF_ENGINE);
  const off = await renderPage("profiles");
  assert.equal(off.includes("require the engine to be Off"), false);

  await setEngine(RUNNING_ENGINE);
  const running = await renderPage("profiles");
  for (const action of ["import-profile", "update-all-profiles", "import-profile-file"]) {
    assert.match(running, new RegExp(`data-action="${action}"`));
    assert.doesNotMatch(running, new RegExp(`data-action="${action}"[^>]*disabled`));
  }
});

test("SOCKS5 links, local YAML, and dropped text use native conversion and never log source credentials", async () => {
  const overrideKeys = ["profiles_snapshot", "import_profile_text", "import_profile_file", "select_profile", "apply_active_profile", "profile_credential_requirements", "profile_credential_presence"];
  const originalResponses = new Map(overrideKeys.map((key) => [key, { present: Object.hasOwn(responses, key), value: responses[key] }]));
  const originalEngine = responses.engine_snapshot;
  const originalLogs = [...state.logs];
  const originalSetup = state.credentialSetup;
  const originalDialog = state.glassDialog;
  const link = "socks://synthetic-user:synthetic-secret@proxy.example.com:29177";
  const importedRecord = { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name: "SOCKS5", bytes: 400, active: false, updated_epoch_secs: 1, source_kind: "local" };
  const references = [
    { id: "11111111-1111-4111-8111-111111111111", kind: "socks5_username" },
    { id: "22222222-2222-4222-8222-222222222222", kind: "socks5_password" },
  ];
  const input = element("input");
  querySelectorElements.set("[data-profile-url]", input);
  responses.import_profile_text = () => {
    responses.profiles_snapshot = { profiles: [{ ...importedRecord, active: false }], invalid_profiles: [] };
    return importedRecord;
  };
  responses.import_profile_file = () => {
    responses.profiles_snapshot = { profiles: [{ ...importedRecord, active: true }], invalid_profiles: [] };
    return importedRecord;
  };
  responses.select_profile = () => {
    responses.profiles_snapshot = { profiles: [{ ...importedRecord, active: true }], invalid_profiles: [] };
    return importedRecord;
  };
  responses.apply_active_profile = { ...importedRecord, applied: false };
  responses.profile_credential_requirements = references;
  responses.profile_credential_presence = references.map((reference) => ({ reference, present: true }));
  try {
    await setEngine(OFF_ENGINE);
    const html = await renderPage("profiles");
    assert.match(html, /HTTPS subscription or node link/u);
    assert.match(html, /accept="\.json,\.yaml,\.yml,\.conf,\.txt,/u);
    // A single-line input strips pasted line breaks; the box must keep them.
    assert.match(html, /<textarea data-profile-url rows="1"/u);
    assert.doesNotMatch(html, /<input data-profile-url/u);
    input.value = link;
    let before = invocationDetails.length;
    await appModule.handleAction("import-profile");
    let calls = invocationDetails.slice(before);
    assert.deepEqual(calls.find(({ command }) => command === "import_profile_text")?.args, { name: null, body: link });
    assert.equal(calls.some(({ command }) => command === "import_profile_url"), false);
    assert.equal(input.value, "", "remove the credential-bearing link after successful import");
    assert.equal(state.credentialSetup.presentCount, 2);
    assert.deepEqual(state.credentialSetup.missing, []);

    const fileInput = element("input");
    const yaml = "proxies:\n  - {type: socks5, name: SOCKS5, server: proxy.example.com, port: 1080, username: synthetic-user, password: synthetic-secret}";
    fileInput.files = [new File([yaml], "nodes.yaml")];
    fileInput.value = "nodes.yaml";
    querySelectorElements.set("[data-profile-file]", fileInput);
    before = invocationDetails.length;
    await appModule.handleAction("import-profile-file");
    calls = invocationDetails.slice(before);
    assert.deepEqual(calls.find(({ command }) => command === "import_profile_text")?.args, { name: "nodes.yaml", body: yaml });
    assert.equal(fileInput.value, "");

    before = invocationDetails.length;
    await emit("tauri://drag-drop", { paths: ["/private/synthetic/nodes.yaml", "/private/synthetic/nodes.txt"] });
    calls = invocationDetails.slice(before).filter(({ command }) => command === "import_profile_file");
    assert.deepEqual(calls.map(({ args }) => args.path), ["/private/synthetic/nodes.yaml", "/private/synthetic/nodes.txt"]);
    assert.ok(calls.every(({ args }) => args.activate === true));
    assert.equal(JSON.stringify(state.logs).includes("synthetic-secret"), false);
    assert.equal(JSON.stringify(state.logs).includes("synthetic-user"), false);

    await setEngine(RUNNING_ENGINE);
    input.value = link;
    before = invocationDetails.length;
    await appModule.handleAction("import-profile");
    const onlineCalls = invocationDetails.slice(before);
    assert.equal(onlineCalls.filter(({ command }) => command === "import_profile_text").length, 1);
    assert.equal(onlineCalls.filter(({ command }) => command === "select_profile").length, 1);
    assert.equal(onlineCalls.some(({ command }) => command === "apply_active_profile"), false, "online import must not dispatch a second renderer restart");

    const links = `${link}\nsocks://second-user:second-secret@proxy.example.com:29178`;
    input.value = links;
    before = invocationDetails.length;
    await appModule.handleAction("import-profile");
    const pastedCalls = invocationDetails.slice(before);
    assert.deepEqual(pastedCalls.find(({ command }) => command === "import_profile_text")?.args, { name: null, body: links }, "every pasted line reaches the importer");
  } finally {
    querySelectorElements.delete("[data-profile-url]");
    querySelectorElements.delete("[data-profile-file]");
    for (const [key, original] of originalResponses) {
      if (original.present) responses[key] = original.value;
      else delete responses[key];
    }
    state.credentialSetup = originalSetup;
    state.glassDialog = originalDialog;
    state.logs = originalLogs;
    await setEngine(originalEngine);
    await reloadButton.click();
  }
});

test("the single-row import box shows its first line whole and no part of the next", async () => {
  const styles = await readStylesheet();
  const body = styles.match(/^\.cfw-url-box textarea\s*\{(?<body>[^}]*)\}/mu)?.groups.body;
  assert.ok(body, "the import box rule exists");
  const rule = Object.fromEntries(
    body.split(";").map((declaration) => declaration.split(":").map((part) => part.trim())).filter(([property]) => property),
  );
  // Overflow clips at the padding box: vertical padding would show the top of a
  // pasted second line, so one line fills the box inside its 1px borders.
  assert.equal(rule.overflow, "hidden");
  assert.equal(rule["box-sizing"], undefined, "the box inherits the global border-box sizing");
  assert.match(styles, /^\*\s*\{[^}]*box-sizing:\s*border-box/mu);
  assert.equal(rule.height, "45px");
  assert.match(rule.border, /^1px solid /u);
  assert.equal(rule.padding, "0 48px 0 12px");
  assert.equal(rule["line-height"], "43px");
});
