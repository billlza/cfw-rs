// Credential and prompt dialogs: the web markup, confirmations, native prompts
// over the page backdrop, cancellation, and refusals.
import assert from "node:assert/strict";
import test from "node:test";
import { t, getLocale, setLocale } from "../src/i18n.js";
import {
  OFF_ENGINE, PROFILE_ID, RUNNING_ENGINE, appModule, deferred, documentListeners, glassRoot,
  initialLiveSettings, interactiveElement, invocationDetails, invoked, querySelectorAllElements,
  rejected, renderPage, responses, setEngine, state,
} from "./support/render-harness.mjs";

test("the credential dialog asks for missing values only while the engine is Off", async () => {
  const setup = {
    profileId: PROFILE_ID,
    profileName: "Work",
    requiredCount: 2,
    presentCount: 1,
    missing: [{ id: PROFILE_ID, kind: "trojan_password" }],
    vaultAvailable: true,
    error: null,
  };

  await setEngine(RUNNING_ENGINE);
  state.glassDialog = { kind: "credentials", id: PROFILE_ID };
  state.credentialSetup = setup;
  glassRoot.innerHTML = "";
  await renderPage("general");
  assert.equal(glassRoot.innerHTML.includes("Store credentials"), false);
  assert.ok(glassRoot.innerHTML.includes("Stop the core before credential maintenance"));

  await setEngine(OFF_ENGINE);
  state.glassDialog = { kind: "credentials", id: PROFILE_ID };
  state.credentialSetup = setup;
  glassRoot.innerHTML = "";
  await renderPage("general");
  for (const needle of ["Store credentials", "Trojan Password", "1 of 2"]) {
    assert.ok(glassRoot.innerHTML.includes(needle), `credential dialog is missing "${needle}"`);
  }

  state.credentialSetup = {
    profileId: PROFILE_ID,
    profileName: "Work",
    requiredCount: null,
    presentCount: null,
    missing: [],
    vaultAvailable: false,
    error: "vault unavailable",
  };
  glassRoot.innerHTML = "";
  await renderPage("general");
  assert.ok(
    glassRoot.innerHTML.includes("nothing is assumed missing"),
    "the credential dialog must fail closed when the vault cannot answer",
  );
  state.glassDialog = null;
  state.credentialSetup = null;
});

const PROMPT_DIALOGS = {
  delete: {
    dialog: () => ({ kind: "delete", id: PROFILE_ID }),
    title: "Delete profile",
    message: "Delete “Work”? This removes the managed profile from the repository.",
    web: `
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Delete profile">
          <h3>Delete profile</h3>
          <p class="glass-dialog-copy">Delete “Work”? This removes the managed profile from the repository.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>No</button>
            <button type="button" class="glass-btn danger" data-glass-delete-confirm="${PROFILE_ID}">Yes</button>
          </div>
        </div>
      `,
  },
  reset: {
    dialog: () => ({ kind: "reset-settings" }),
    title: "Reset all settings",
    message: "Reset appearance, silent start and update preferences to their defaults? Imported profiles, the selected profile and the Start with macOS registration are all kept.",
    web: `
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Reset settings">
          <h3>Reset all settings</h3>
          <p class="glass-dialog-copy">Reset appearance, silent start and update preferences to their defaults? Imported profiles, the selected profile and the Start with macOS registration are all kept.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>No</button>
            <button type="button" class="glass-btn danger" data-glass-reset-confirm>Yes</button>
          </div>
        </div>
      `,
  },
  info: {
    dialog: () => ({ kind: "info", payload: { title: "System DNS", body: "never <written>" } }),
    title: "System DNS",
    message: "never <written>",
    web: `
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Info">
          <h3>System DNS</h3>
          <p class="glass-dialog-copy">never &lt;written&gt;</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button></div>
        </div>
      `,
  },
};

test("prompt dialogs keep their exact web markup when the host has no native prompt", async () => {
  assert.equal(state.payload.native_ui.prompt_dialog, false);
  const before = invoked.length;
  try {
    for (const [name, { dialog, web }] of Object.entries(PROMPT_DIALOGS)) {
      state.glassDialog = dialog();
      glassRoot.innerHTML = "";
      await renderPage("feedback");
      assert.equal(glassRoot.innerHTML, web, `the ${name} dialog changed its web markup`);
    }
    state.glassDialog = { kind: "info" };
    await renderPage("feedback");
    assert.match(glassRoot.innerHTML, /<h3>Info<\/h3>\s*<p class="glass-dialog-copy"><\/p>/u,
      "an information dialog without a payload keeps its default title and empty body");
    assert.deepEqual(invoked.slice(before).filter((command) => command.endsWith("_native_prompt_dialog")), [],
      "a host without the native prompt never invokes its presentation commands");
  } finally {
    state.glassDialog = null;
    await renderPage("feedback");
  }
});

test("web confirmations run their business command once and keep a refused dialog open", async () => {
  const confirmDelete = interactiveElement();
  confirmDelete.dataset.glassDeleteConfirm = PROFILE_ID;
  const confirmReset = interactiveElement();
  const logged = (message) => state.logs.filter((entry) => entry.message === message).length;
  const count = (command) => invoked.filter((name) => name === command).length;
  try {
    querySelectorAllElements.set("[data-glass-delete-confirm]", [confirmDelete]);
    querySelectorAllElements.set("[data-glass-reset-confirm]", [confirmReset]);
    await renderPage("profiles");

    const refusedDelete = PROMPT_DIALOGS.delete.dialog();
    state.glassDialog = refusedDelete;
    rejected.delete_profile = "repository is locked";
    invoked.length = 0;
    await confirmDelete.trigger("click");
    assert.equal(count("delete_profile"), 1);
    assert.equal(state.glassDialog, refusedDelete, "a refused deletion keeps its dialog");
    assert.equal(glassRoot.innerHTML, PROMPT_DIALOGS.delete.web);
    assert.equal(logged("Delete failed: repository is locked"), 1);

    delete rejected.delete_profile;
    responses.delete_profile = true;
    invoked.length = 0;
    await confirmDelete.trigger("click");
    assert.equal(count("delete_profile"), 1);
    assert.deepEqual(invocationDetails.findLast(({ command }) => command === "delete_profile").args, { id: PROFILE_ID });
    assert.equal(state.glassDialog, null);
    assert.equal(glassRoot.innerHTML, "");
    assert.equal(logged("Profile deleted: Work"), 1);

    const refusedReset = PROMPT_DIALOGS.reset.dialog();
    state.glassDialog = refusedReset;
    rejected.reset_settings_snapshot = "settings store is read-only";
    invoked.length = 0;
    await confirmReset.trigger("click");
    assert.equal(count("reset_settings_snapshot"), 1);
    assert.equal(state.glassDialog, refusedReset, "a refused reset keeps its dialog");
    assert.equal(glassRoot.innerHTML, PROMPT_DIALOGS.reset.web);
    assert.equal(logged("Reset failed: settings store is read-only"), 1);

    delete rejected.reset_settings_snapshot;
    responses.reset_settings_snapshot = structuredClone(initialLiveSettings);
    const resets = logged("Preferences reset to defaults");
    invoked.length = 0;
    await confirmReset.trigger("click");
    assert.equal(count("reset_settings_snapshot"), 1);
    assert.equal(state.glassDialog, null);
    assert.equal(logged("Preferences reset to defaults"), resets + 1);
  } finally {
    delete rejected.delete_profile;
    delete rejected.reset_settings_snapshot;
    delete responses.delete_profile;
    delete responses.reset_settings_snapshot;
    querySelectorAllElements.clear();
    state.glassDialog = null;
    await renderPage("feedback");
  }
});

test("a confirmation that finishes late closes only the dialog that started it", async () => {
  const confirmDelete = interactiveElement();
  confirmDelete.dataset.glassDeleteConfirm = PROFILE_ID;
  const confirmReset = interactiveElement();
  const logged = (message) => state.logs.filter((entry) => entry.message === message).length;
  const removal = deferred();
  const reset = deferred();
  try {
    querySelectorAllElements.set("[data-glass-delete-confirm]", [confirmDelete]);
    querySelectorAllElements.set("[data-glass-reset-confirm]", [confirmReset]);
    responses.delete_profile = () => removal.promise;
    responses.reset_settings_snapshot = () => reset.promise;
    for (const [confirm, question, answer, report] of [
      [confirmDelete, PROMPT_DIALOGS.delete.dialog(), () => removal.resolve(true), "Profile deleted: Work"],
      [confirmReset, PROMPT_DIALOGS.reset.dialog(), () => reset.resolve(structuredClone(initialLiveSettings)), "Preferences reset to defaults"],
    ]) {
      state.glassDialog = question;
      await renderPage("profiles");
      const running = confirm.trigger("click");
      // The user dismisses the question and opens a notice while the request
      // is still running. The late success must not close that notice.
      const notice = PROMPT_DIALOGS.info.dialog();
      state.glassDialog = notice;
      await renderPage("profiles");
      const reports = logged(report);
      answer();
      await running;
      assert.equal(logged(report), reports + 1);
      assert.equal(state.glassDialog, notice, `${question.kind}: the notice opened meanwhile stays open`);
      assert.equal(glassRoot.innerHTML, PROMPT_DIALOGS.info.web);
    }
  } finally {
    delete responses.delete_profile;
    delete responses.reset_settings_snapshot;
    querySelectorAllElements.clear();
    state.glassDialog = null;
    await renderPage("feedback");
  }
});

const PROMPT_BACKDROP = '<div class="glass-dialog-backdrop" data-glass-dismiss></div>';

const PROMPT_CONFIRMATION = [{ id: "cancel", title: "No", role: "cancel" }, { id: "confirm", title: "Yes", role: "destructive" }];

/// Runs `body` against a host whose boot payload admits the native prompt. The
/// page keeps one presentation adapter, so every case leaves no dialog behind.
async function withNativePrompt(body) {
  const prior = { enabled: state.payload.native_ui.prompt_dialog, handoff: state.migrationHandoff,
    handoffStatus: state.migrationHandoffStatus, theme: document.documentElement.dataset.theme, locale: getLocale() };
  const flush = async () => { for (let i = 0; i < 6; i++) await new Promise((resolve) => setImmediate(resolve)); };
  const native = (kind) => invocationDetails.filter(({ command }) => command === `${kind}_native_prompt_dialog`).map(({ args }) => args);
  const backdrop = interactiveElement("div");
  const deleteFromMenu = interactiveElement();
  deleteFromMenu.dataset.profileMenu = "delete";
  deleteFromMenu.dataset.profileId = PROFILE_ID;
  responses.present_native_prompt_dialog = null;
  responses.update_native_prompt_dialog = true;
  responses.dismiss_native_prompt_dialog = true;
  try {
    state.payload.native_ui.prompt_dialog = true;
    state.glassDialog = null;
    querySelectorAllElements.set("[data-glass-dismiss]", [backdrop]);
    querySelectorAllElements.set("[data-profile-menu]", [deleteFromMenu]);
    await renderPage("profiles"); await flush();
    await body({ flush, native, backdrop, deleteFromMenu,
      logged: (message) => state.logs.filter((entry) => entry.message === message).length,
      count: (command) => invoked.filter((name) => name === command).length,
      escape: async () => {
        for (const listener of documentListeners.get("keydown") ?? []) listener({ key: "Escape", preventDefault() {} });
        await flush();
      } });
  } finally {
    for (const command of ["present_native_prompt_dialog", "delete_profile", "reset_settings_snapshot"]) delete rejected[command];
    state.migrationHandoff = prior.handoff;
    state.migrationHandoffStatus = prior.handoffStatus;
    document.documentElement.dataset.theme = prior.theme;
    setLocale(prior.locale);
    state.glassDialog = null;
    await renderPage("feedback"); await flush();
    state.payload.native_ui.prompt_dialog = prior.enabled;
    querySelectorAllElements.clear();
    for (const command of ["present_native_prompt_dialog", "update_native_prompt_dialog", "dismiss_native_prompt_dialog",
      "delete_profile", "reset_settings_snapshot"]) delete responses[command];
  }
}

test("a native prompt host presents each dialog over the page backdrop and opening issues no business IPC", async () => {
  await withNativePrompt(async ({ flush, native, backdrop, deleteFromMenu, count, escape }) => {
    invoked.length = 0;
    const opened = async (open) => {
      const before = invoked.length;
      await open(); await flush();
      assert.deepEqual(invoked.slice(before), ["present_native_prompt_dialog"], "opening a prompt only presents it");
      assert.equal(glassRoot.innerHTML, PROMPT_BACKDROP, "the page keeps only its backdrop under the native panel");
      return native("present").at(-1);
    };

    const removal = await opened(() => deleteFromMenu.trigger("click"));
    assert.deepEqual(removal.request, {
      requestId: removal.request.requestId, sequence: 1, acknowledgedSubmission: 0,
      locale: "en", appearance: document.documentElement.dataset.theme,
      title: PROMPT_DIALOGS.delete.title, message: PROMPT_DIALOGS.delete.message, buttons: PROMPT_CONFIRMATION,
      transportFailure: "The native dialog could not deliver this action. Close it and try again.",
    });
    assert.match(removal.request.requestId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
    assert.ok(["light", "dark"].includes(removal.request.appearance));
    const stable = { presents: native("present").length, updates: native("update").length };
    await renderPage("profiles"); await flush();
    assert.deepEqual({ presents: native("present").length, updates: native("update").length }, stable,
      "re-rendering an unchanged prompt sends nothing");
    assert.equal(glassRoot.innerHTML, PROMPT_BACKDROP);

    // The dimmed page under the panel still dismisses, as it does for the web dialog.
    await backdrop.trigger("click"); await flush();
    assert.equal(state.glassDialog, null);
    assert.equal(glassRoot.innerHTML, "");
    assert.equal(native("dismiss").at(-1).requestId, removal.request.requestId);
    removal.completion.onmessage({ kind: "activate", requestId: removal.request.requestId, submissionId: 1, buttonId: "confirm" });
    await flush();
    assert.equal(count("delete_profile"), 0, "a dismissed prompt can no longer confirm");

    const reset = await opened(() => appModule.handleAction("reset-settings"));
    assert.equal(reset.request.title, PROMPT_DIALOGS.reset.title);
    assert.equal(reset.request.message, PROMPT_DIALOGS.reset.message);
    assert.deepEqual(reset.request.buttons, PROMPT_CONFIRMATION);
    setLocale("ja");
    await renderPage("profiles"); await flush();
    const translated = native("update").at(-1).request;
    assert.equal(translated.requestId, reset.request.requestId);
    assert.deepEqual([translated.sequence, translated.acknowledgedSubmission, translated.locale], [2, 0, "ja"]);
    assert.equal(translated.title, "すべての設定をリセット");
    assert.deepEqual(translated.buttons.map(({ id, title }) => [id, title]), [["cancel", "いいえ"], ["confirm", "はい"]]);
    setLocale("en");
    await escape();
    assert.equal(state.glassDialog, null);
    assert.equal(native("dismiss").at(-1).requestId, reset.request.requestId);
    assert.equal(count("reset_settings_snapshot"), 0);

    const notice = await opened(() => appModule.handleAction("allow-lan-info"));
    assert.equal(notice.request.title, "Allow LAN");
    assert.equal(notice.request.message, t("LAN sharing uses a separate listener restricted to explicitly trusted private source networks."));
    assert.deepEqual(notice.request.buttons, [{ id: "cancel", title: "Close", role: "cancel" }]);
    const dismissals = native("dismiss").length;
    notice.completion.onmessage({ kind: "closed", requestId: notice.request.requestId });
    await flush();
    assert.equal(state.glassDialog, null, "the native Close button closes the dashboard's dialog");
    assert.equal(glassRoot.innerHTML, "");
    assert.equal(native("dismiss").length, dismissals, "a panel that closed itself is not dismissed again");
  });
});

test("native confirmations run the web confirm path once and a refusal keeps the prompt usable", async () => {
  await withNativePrompt(async ({ flush, native, deleteFromMenu, logged, count }) => {
    await appModule.handleAction("reset-settings"); await flush();
    const resetDialog = state.glassDialog;
    const reset = native("present").at(-1);
    const activate = (prompt, submissionId) => {
      prompt.completion.onmessage({ kind: "activate", requestId: prompt.request.requestId, submissionId, buttonId: "confirm" });
      return flush();
    };
    const dismissed = (prompt) => native("dismiss").filter(({ requestId }) => requestId === prompt.request.requestId).length;

    rejected.reset_settings_snapshot = "settings store is read-only";
    let refusals = logged("Reset failed: settings store is read-only");
    invoked.length = 0;
    await activate(reset, 1);
    assert.equal(count("reset_settings_snapshot"), 1);
    assert.equal(state.glassDialog, resetDialog, "a refused reset keeps its prompt");
    assert.equal(glassRoot.innerHTML, PROMPT_BACKDROP);
    assert.equal(logged("Reset failed: settings store is read-only"), refusals + 1);
    assert.equal(dismissed(reset), 0);
    const released = native("update").at(-1).request;
    assert.deepEqual([released.requestId, released.sequence, released.acknowledgedSubmission],
      [reset.request.requestId, 2, 1], "the refused action is acknowledged, so the native buttons work again");

    delete rejected.reset_settings_snapshot;
    responses.reset_settings_snapshot = structuredClone(initialLiveSettings);
    const resets = logged("Preferences reset to defaults");
    invoked.length = 0;
    await activate(reset, 2);
    assert.equal(count("reset_settings_snapshot"), 1);
    assert.equal(state.glassDialog, null);
    assert.equal(glassRoot.innerHTML, "");
    assert.equal(logged("Preferences reset to defaults"), resets + 1);
    assert.equal(dismissed(reset), 1, "the dashboard dismisses the prompt after its action succeeded");

    await deleteFromMenu.trigger("click"); await flush();
    const removalDialog = state.glassDialog;
    const removal = native("present").at(-1);
    rejected.delete_profile = "repository is locked";
    refusals = logged("Delete failed: repository is locked");
    invoked.length = 0;
    await activate(removal, 1);
    assert.equal(count("delete_profile"), 1);
    assert.equal(state.glassDialog, removalDialog, "a refused deletion keeps its prompt");
    assert.equal(logged("Delete failed: repository is locked"), refusals + 1);
    assert.equal(native("update").at(-1).request.acknowledgedSubmission, 1);
    assert.equal(native("update").at(-1).request.requestId, removal.request.requestId);

    delete rejected.delete_profile;
    responses.delete_profile = true;
    const deletions = logged("Profile deleted: Work");
    invoked.length = 0;
    await activate(removal, 2);
    assert.equal(count("delete_profile"), 1);
    assert.deepEqual(invocationDetails.findLast(({ command }) => command === "delete_profile").args, { id: PROFILE_ID });
    assert.equal(state.glassDialog, null);
    assert.equal(logged("Profile deleted: Work"), deletions + 1);
    assert.equal(dismissed(removal), 1);
  });
});

test("the native prompt can be cancelled while its action runs, as the page dialog can", async () => {
  await withNativePrompt(async ({ flush, native, logged, count }) => {
    const reset = deferred();
    responses.reset_settings_snapshot = () => reset.promise;
    await appModule.handleAction("reset-settings"); await flush();
    const prompt = native("present").at(-1);
    invoked.length = 0;
    prompt.completion.onmessage({ kind: "activate", requestId: prompt.request.requestId, submissionId: 1, buttonId: "confirm" });
    await flush();
    assert.equal(count("reset_settings_snapshot"), 1);
    assert.equal(glassRoot.innerHTML, PROMPT_BACKDROP);
    // No or Escape in the panel while the request is still running.
    prompt.completion.onmessage({ kind: "closed", requestId: prompt.request.requestId });
    await flush();
    assert.equal(state.glassDialog, null, "the running action does not hold the dialog open");
    assert.equal(glassRoot.innerHTML, "");
    const resets = logged("Preferences reset to defaults");
    reset.resolve(structuredClone(initialLiveSettings));
    await flush();
    assert.equal(logged("Preferences reset to defaults"), resets + 1, "the action still completes and reports");
    assert.equal(count("reset_settings_snapshot"), 1);
    assert.equal(state.glassDialog, null);
    assert.deepEqual(invoked.filter((command) => command.endsWith("_native_prompt_dialog")), [],
      "a panel that closed itself needs no update or dismissal");
  });
});

test("a refused native prompt keeps its text and states the failure without a confirmation", async () => {
  await withNativePrompt(async ({ flush, logged, count, escape }) => {
    // The alert and the log line pass through the diagnostic redaction.
    rejected.present_native_prompt_dialog = "native prompt dialog presentation rejected (status 0) token=hunter2";
    const refusal = "native prompt dialog presentation rejected (status 0) token=[redacted]";
    const report = `Native presentation of “Reset all settings” failed: ${refusal}`;
    let reported = logged(report);
    invoked.length = 0;
    await appModule.handleAction("reset-settings"); await flush();
    assert.equal(glassRoot.innerHTML, `${PROMPT_BACKDROP}
        <div class="glass-dialog" role="dialog" aria-label="Reset all settings">
          <h3>Reset all settings</h3>
          <p class="glass-dialog-copy">${PROMPT_DIALOGS.reset.message}</p>
          <p class="glass-dialog-copy warning" role="alert">${refusal}</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>No</button></div>
        </div>`, "the question and the failure are stated and only dismissal is offered");
    assert.equal(logged(report), reported + 1);
    assert.equal(state.logs.some((entry) => entry.message.includes("hunter2")), false);
    assert.equal(count("reset_settings_snapshot"), 0);
    await escape();
    assert.equal(state.glassDialog, null);
    assert.equal(glassRoot.innerHTML, "");

    // A notice raised while its window is hidden is refused by the host. Its
    // text must still be shown, or the user never learns what happened.
    const hidden = "native prompt dialog parent is unavailable (status 2)";
    rejected.present_native_prompt_dialog = hidden;
    const notice = t("LAN sharing uses a separate listener restricted to explicitly trusted private source networks.");
    reported = logged(`Native presentation of “Allow LAN” failed: ${hidden}`);
    await appModule.handleAction("allow-lan-info"); await flush();
    assert.equal(glassRoot.innerHTML, `${PROMPT_BACKDROP}
        <div class="glass-dialog" role="dialog" aria-label="Allow LAN">
          <h3>Allow LAN</h3>
          <p class="glass-dialog-copy">${notice}</p>
          <p class="glass-dialog-copy warning" role="alert">${hidden}</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button></div>
        </div>`);
    assert.equal(logged(`Native presentation of “Allow LAN” failed: ${hidden}`), reported + 1);
    await escape();
    assert.equal(glassRoot.innerHTML, "");
  });
});

test("dialogs the host or the native frame cannot take stay in the page", async () => {
  await withNativePrompt(async ({ flush, native, escape }) => {
    const presents = native("present").length;
    const pageNotice = /<div class="glass-dialog" role="dialog" aria-label="Info">\s*<h3>Allow LAN<\/h3>/u;
    // A migration handoff window, and a host with a handoff in progress,
    // refuse every presentation command.
    state.migrationHandoff = true;
    await appModule.handleAction("allow-lan-info"); await flush();
    assert.match(glassRoot.innerHTML, pageNotice);
    state.migrationHandoff = false;
    await escape();
    const idle = state.migrationHandoffStatus;
    state.migrationHandoffStatus = { state: "in_progress" };
    await appModule.handleAction("allow-lan-info"); await flush();
    assert.match(glassRoot.innerHTML, pageNotice);
    state.migrationHandoffStatus = idle;
    await escape();
    // Until the page theme is resolved there is no appearance to give the panel.
    const theme = document.documentElement.dataset.theme;
    delete document.documentElement.dataset.theme;
    await appModule.handleAction("allow-lan-info"); await flush();
    assert.match(glassRoot.innerHTML, pageNotice);
    document.documentElement.dataset.theme = theme;
    await escape();

    // Text beyond the bounded native frame keeps the page dialog, uncut.
    const long = "x".repeat(4097);
    state.glassDialog = { kind: "info", payload: { title: "Legacy migration failed", body: long } };
    await renderPage("profiles"); await flush();
    assert.ok(glassRoot.innerHTML.includes(`<p class="glass-dialog-copy">${long}</p>`));
    state.glassDialog = { kind: "copy", id: PROFILE_ID };
    await renderPage("profiles"); await flush();
    assert.match(glassRoot.innerHTML, /data-glass-copy-confirm/u);
    assert.equal(native("present").length, presents, "none of these is presented natively");

    // Replacing a native prompt with a page dialog releases the panel.
    await appModule.handleAction("allow-lan-info"); await flush();
    const notice = native("present").at(-1);
    assert.equal(glassRoot.innerHTML, PROMPT_BACKDROP);
    await appModule.handleAction("dns-query"); await flush();
    assert.match(glassRoot.innerHTML, /Resolve through the running engine/u);
    assert.equal(native("dismiss").at(-1).requestId, notice.request.requestId);
  });
});
