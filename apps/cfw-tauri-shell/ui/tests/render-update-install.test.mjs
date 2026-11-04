// In-app update installation in the About dialog: what startup asks about, the
// offers each host supports, preparation and installation, and attempts that
// ended or were withdrawn.
import assert from "node:assert/strict";
import test from "node:test";
import {
  OVERLAY_SLOTS, PROFILE_ID, UPDATE_COMMANDS, appModule, emit, glassRoot, interactiveElement,
  invocationDetails, querySelectorAllElements, rejected, renderPage, responses,
  startupUpdateReport, state,
} from "./support/render-harness.mjs";

const IDLE_INSTALL = Object.freeze({
  phase: "idle", version: null, downloaded: 0, total: null, failure: null, ended: null,
});

test("startup asks once what the previous update installation left behind", () => {
  assert.equal(startupUpdateReport.queries, 1);
  assert.deepEqual(
    startupUpdateReport.errors, [],
    "an absent installation record is not reported as a failure",
  );
  assert.equal(startupUpdateReport.dialog, null, "and nothing is shown for it");
  assert.deepEqual(startupUpdateReport.install, IDLE_INSTALL, "nor is any installation re-attached");
});

test("the About dialog offers in-app installation only where the host supports it", async () => {
  const about = (install, version = "0.4.1") => ({
    kind: "product-about",
    payload: { phase: "idle", update: { available: true, version, install } },
  });
  const original = { dialog: state.glassDialog, install: state.updateInstall };
  const render = async () => {
    glassRoot.innerHTML = "";
    await renderPage("general");
    return glassRoot.innerHTML;
  };
  try {
    state.updateInstall = { ...IDLE_INSTALL };
    state.glassDialog = about({ supported: true });
    let html = await render();
    assert.ok(html.includes("data-glass-update-install>Install Update v0.4.1<"));
    assert.ok(html.includes('class="glass-btn ghost" data-glass-open-update'),
      "the download page stays available as the secondary action");
    assert.ok(html.includes('<div class="product-about-status">Update available: v0.4.1</div>'),
      "without an installation the dialog keeps its own status line");

    for (const install of [{ supported: false, code: "not_in_applications" }, undefined]) {
      state.glassDialog = about(install);
      html = await render();
      assert.equal(html.includes("data-glass-update-"), false);
      assert.ok(html.includes('class="glass-btn" data-glass-open-update'),
        "without in-app installation the dialog is exactly the release-page dialog");
    }

    const nothingPresented = {
      kind: "product-about",
      payload: { phase: "idle", update: { available: false, current: "0.4.0", error: "offline" } },
    };
    for (const presented of [about({ supported: true }), about({ supported: true }, "0.4.2"), nothingPresented]) {
      const context = JSON.stringify(presented.payload.update);
      state.glassDialog = presented;
      state.updateInstall = { ...IDLE_INSTALL, phase: "downloading", version: "0.4.1", downloaded: 30, total: 120 };
      html = await render();
      assert.ok(html.includes("Downloading update… 25%"), context);
      assert.ok(html.includes("data-glass-update-cancel"), context);
      assert.equal(html.includes("data-glass-open-update"), false, context);
      assert.equal(html.includes("data-glass-update-install"), false, context);
      assert.ok(html.includes("data-glass-check-update disabled"), context);
      assert.ok(html.includes("data-glass-dismiss disabled"), context);

      state.updateInstall = { ...IDLE_INSTALL, phase: "ready", version: "0.4.1" };
      html = await render();
      assert.ok(html.includes("data-glass-update-commit>Install and Relaunch<"), context);
      assert.ok(html.includes("data-glass-update-cancel"), context);
      assert.ok(
        html.includes("v0.4.1 is ready to install. Clash for Mac will stop the core, quit, and reopen."),
        `the staged release is named whatever is presented: ${context}`,
      );
      assert.equal(html.includes("data-glass-open-update"), false, context);
      assert.equal(html.includes("data-glass-update-install"), false, context);
      assert.equal(html.includes("data-glass-check-update disabled"), false, context);
    }

    state.glassDialog = about({ supported: true });
    state.updateInstall = {
      ...IDLE_INSTALL, version: "0.4.1", failure: { code: "signature_mismatch", category: "authenticity" },
    };
    html = await render();
    assert.ok(html.includes("(signature_mismatch)"));
    assert.equal(html.includes("data-glass-open-update"), false,
      "a download that failed its signature is not answered with another download");
    assert.equal(html.includes("data-glass-update-install"), false);

    state.glassDialog = about({ supported: false, code: "release_failed_authentication" });
    state.updateInstall = { ...IDLE_INSTALL };
    html = await render();
    assert.ok(
      html.includes("The downloaded update is not the signed release and was discarded. Do not install it from another source. (release_failed_authentication)"),
      "the host's verdict is shown by a page that has no record of the failure",
    );
    assert.equal(html.includes("data-glass-open-update"), false);
    assert.equal(html.includes("data-glass-update-"), false);

    state.glassDialog = about({ supported: true });
    for (const [ended, reason] of [
      [{ failure: { code: "network", category: "network" } }, "The download did not complete. Check the connection and try again. (network)"],
      [{ ended: "cancelled" }, "Update download cancelled"],
      [{ ended: "unreported" }, "The update installation is no longer in progress. Check for updates again."],
    ]) {
      state.updateInstall = { ...IDLE_INSTALL, version: "0.4.1", ...ended };
      html = await render();
      assert.ok(html.includes(`<div class="product-about-status">${reason}</div>`), reason);
      assert.equal(html.includes("data-glass-update-"), false, `${reason}: the consumed release is not offered for installation`);
      assert.equal(html.includes("data-glass-open-update"), false, `${reason}: nor for download`);
      assert.ok(html.includes("data-glass-check-update >Check for Update<"), `${reason}: a fresh check stays available`);
      assert.equal(html.includes("data-glass-dismiss disabled"), false, `${reason}: and so does Close`);
    }

    state.glassDialog = { kind: "product-about", payload: { phase: "checking", update: { available: true, version: "0.4.1", install: { supported: true } } } };
    state.updateInstall = { ...IDLE_INSTALL };
    html = await render();
    assert.equal(html.includes("data-glass-update-install"), false, "nothing is offered while a check is running");
  } finally {
    state.glassDialog = original.dialog;
    state.updateInstall = original.install;
  }
});

test("the About dialog buttons drive preparation, installation and cancellation through the host", async () => {
  const original = { dialog: state.glassDialog, install: state.updateInstall, info: state.updateInfo };
  const buttons = { install: interactiveElement(), commit: interactiveElement(), cancel: interactiveElement() };
  querySelectorAllElements.set("[data-glass-update-install]", [buttons.install]);
  querySelectorAllElements.set("[data-glass-update-commit]", [buttons.commit]);
  querySelectorAllElements.set("[data-glass-update-cancel]", [buttons.cancel]);
  const issued = (command) => invocationDetails.filter((entry) => entry.command === command);
  try {
    await emit("cfw://update-available", {
      available: true, version: "0.4.1", current: "0.4.0", install: { supported: true },
    });
    assert.deepEqual(state.updateInfo.install, { supported: true });
    state.glassDialog = { kind: "product-about", payload: { phase: "idle", update: state.updateInfo } };
    state.updateInstall = { ...IDLE_INSTALL };
    await renderPage("general");

    responses.prepare_update_install = { version: "0.4.1" };
    const prepared = issued("prepare_update_install").length;
    await buttons.install.trigger("click");
    assert.deepEqual(issued("prepare_update_install").slice(prepared).map(({ args }) => args),
      [{ expectedVersion: "0.4.1" }]);
    assert.equal(state.updateInstall.phase, "ready");
    assert.ok(glassRoot.innerHTML.includes("data-glass-update-commit"),
      "the dialog re-renders when the host stages the release");

    await emit("cfw://update-progress", { phase: "downloading", version: "0.4.1", downloaded: 1, total: 2 });
    assert.equal(state.updateInstall.phase, "ready", "late progress never unstages a release");

    responses.commit_update_install = () => {
      throw { code: "engine_stop_failed", category: "engine" };
    };
    await buttons.commit.trigger("click");
    assert.equal(state.updateInstall.phase, "ready");
    assert.ok(glassRoot.innerHTML.includes("The core could not be stopped. Stop the core and try again. (engine_stop_failed)"));

    responses.cancel_update_install = { cancelled: "staged" };
    const cancellations = issued("cancel_update_install").length;
    await buttons.cancel.trigger("click");
    assert.equal(issued("cancel_update_install").length, cancellations + 1);
    assert.deepEqual(state.updateInstall, { ...IDLE_INSTALL, version: "0.4.1", ended: "cancelled" });

    state.updateInstall = { ...IDLE_INSTALL, phase: "ready", version: "0.4.1" };
    responses.commit_update_install = { version: "0.4.1" };
    await buttons.commit.trigger("click");
    assert.deepEqual(issued("commit_update_install").at(-1).args, { expectedVersion: "0.4.1" });
    assert.equal(state.updateInstall.phase, "installing");
    assert.ok(glassRoot.innerHTML.includes("Clash for Mac will reopen automatically"));
  } finally {
    for (const command of ["prepare_update_install", "commit_update_install", "cancel_update_install"]) {
      delete responses[command];
    }
    querySelectorAllElements.clear();
    state.glassDialog = original.dialog;
    state.updateInstall = original.install;
    state.updateInfo = original.info;
  }
});

const RELEASE = Object.freeze({
  available: true, version: "0.4.1", current: "0.4.0", install: { supported: true },
});

const issuedCount = (command) => invocationDetails.filter((entry) => entry.command === command).length;

const updateOffers = () => ({
  install: glassRoot.innerHTML.includes("data-glass-update-install"),
  download: glassRoot.innerHTML.includes("data-glass-open-update"),
});

const NEITHER_OFFER = Object.freeze({ install: false, download: false });

const BOTH_OFFERS = Object.freeze({ install: true, download: true });

/// Runs `body` with the About dialog's buttons bound, no overlay open and no
/// installation followed, then restores every fixture an update test scripts.
async function withUpdateDialog(body) {
  const original = {
    overlays: OVERLAY_SLOTS.map((slot) => state[slot]),
    install: state.updateInstall,
    info: state.updateInfo,
    check: responses.check_for_updates,
    resolve: responses.resolve_update_install,
  };
  const buttons = {
    install: interactiveElement(), commit: interactiveElement(), cancel: interactiveElement(),
    open: interactiveElement(), check: interactiveElement(),
  };
  querySelectorAllElements.set("[data-glass-update-install]", [buttons.install]);
  querySelectorAllElements.set("[data-glass-update-commit]", [buttons.commit]);
  querySelectorAllElements.set("[data-glass-update-cancel]", [buttons.cancel]);
  querySelectorAllElements.set("[data-glass-open-update]", [buttons.open]);
  querySelectorAllElements.set("[data-glass-check-update]", [buttons.check]);
  try {
    for (const slot of OVERLAY_SLOTS) state[slot] = null;
    state.updateInstall = { ...IDLE_INSTALL };
    await body(buttons);
  } finally {
    for (const command of UPDATE_COMMANDS) delete responses[command];
    delete rejected.check_for_updates;
    responses.check_for_updates = original.check;
    responses.resolve_update_install = original.resolve;
    querySelectorAllElements.clear();
    OVERLAY_SLOTS.forEach((slot, index) => { state[slot] = original.overlays[index]; });
    state.updateInstall = original.install;
    state.updateInfo = original.info;
  }
}

test("after an installation attempt ended the About dialog offers nothing the host would reject", async () => {
  await withUpdateDialog(async (buttons) => {
    // Like the host, every preparation and every opened download page
    // consumes the presented release, and only a check presents it again.
    const host = { presented: false, staging: "succeeds" };
    responses.check_for_updates = () => {
      host.presented = true;
      return RELEASE;
    };
    responses.prepare_update_install = () => {
      if (!host.presented) throw { code: "missing_authorization", category: "state" };
      host.presented = false;
      if (host.staging === "fails") throw { code: "network", category: "network" };
      return { version: "0.4.1" };
    };
    responses.open_available_update = () => {
      if (!host.presented) throw new Error("no validated update check authorizes this release page");
      host.presented = false;
      return { opened: true, installed: false, version: "0.4.1" };
    };
    responses.cancel_update_install = { cancelled: "staged" };
    const earlier = new Set(state.logs);
    const rejectedByHost = () => state.logs.filter((entry) => !earlier.has(entry) && entry.source === "updater"
      && (entry.message.includes("(missing_authorization)") || entry.message.startsWith("Could not open update")));
    const checkAndCloseRemain = (context) => {
      assert.ok(glassRoot.innerHTML.includes("data-glass-check-update >Check for Update<"), context);
      assert.equal(glassRoot.innerHTML.includes("data-glass-dismiss disabled"), false, context);
    };

    await appModule.handleAction("check-for-updates");
    assert.deepEqual(updateOffers(), BOTH_OFFERS);

    await buttons.install.trigger("click");
    assert.equal(state.updateInstall.phase, "ready");
    await buttons.cancel.trigger("click");
    assert.deepEqual(updateOffers(), NEITHER_OFFER, "a cancelled attempt consumed the presented release");
    assert.ok(glassRoot.innerHTML.includes('<div class="product-about-status">Update download cancelled</div>'));
    checkAndCloseRemain("after a cancelled attempt");
    const prepared = issuedCount("prepare_update_install");
    await buttons.install.trigger("click");
    assert.equal(issuedCount("prepare_update_install"), prepared, "the withdrawn installation issues no command");

    await buttons.check.trigger("click");
    assert.deepEqual(updateOffers(), BOTH_OFFERS, "a fresh check presents the release again");

    host.staging = "fails";
    await buttons.install.trigger("click");
    assert.deepEqual(updateOffers(), NEITHER_OFFER, "a failed attempt consumed the presented release");
    assert.ok(glassRoot.innerHTML.includes("The download did not complete. Check the connection and try again. (network)"));
    checkAndCloseRemain("after a failed attempt");

    host.staging = "succeeds";
    await buttons.check.trigger("click");
    assert.deepEqual(updateOffers(), BOTH_OFFERS, "a fresh check presents the release again");
    await buttons.install.trigger("click");
    assert.equal(state.updateInstall.phase, "ready", "the offered installation is one the host accepts");
    await buttons.cancel.trigger("click");

    await buttons.check.trigger("click");
    assert.deepEqual(updateOffers(), BOTH_OFFERS);
    const opened = issuedCount("open_available_update");
    await buttons.open.trigger("click");
    assert.equal(issuedCount("open_available_update"), opened + 1);
    assert.equal(state.glassDialog, null, "the offered download page is one the host opens");
    assert.deepEqual(rejectedByHost(), [], "the host rejected nothing the dialog offered");
  });
});

test("a staged installation stays in the About dialog whatever a later check presents", async () => {
  await withUpdateDialog(async (buttons) => {
    responses.check_for_updates = RELEASE;
    responses.prepare_update_install = { version: "0.4.1" };
    await appModule.handleAction("check-for-updates");
    await buttons.install.trigger("click");

    const stagedIsShown = (context) => {
      const html = glassRoot.innerHTML;
      assert.deepEqual(state.updateInstall, { ...IDLE_INSTALL, phase: "ready", version: "0.4.1" }, context);
      assert.ok(html.includes("v0.4.1 is ready to install."), context);
      assert.ok(html.includes("data-glass-update-commit>Install and Relaunch<"), context);
      assert.ok(html.includes("data-glass-update-cancel"), context);
      assert.deepEqual(updateOffers(), NEITHER_OFFER, context);
    };
    stagedIsShown("the staged release is the presented one");

    responses.check_for_updates = { ...RELEASE, version: "0.4.2" };
    await buttons.check.trigger("click");
    assert.equal(state.updateInfo.version, "0.4.2");
    stagedIsShown("another release is presented");

    rejected.check_for_updates = "update server unreachable";
    await buttons.check.trigger("click");
    delete rejected.check_for_updates;
    assert.equal(state.updateInfo.available, false);
    assert.equal(state.updateInfo.error, "update server unreachable");
    stagedIsShown("the check failed");

    await emit("cfw://update-available", { available: false, current: "0.4.0" });
    assert.equal(state.updateInfo.error, null);
    stagedIsShown("no release is presented");

    responses.commit_update_install = () => {
      throw { code: "engine_stop_failed", category: "engine" };
    };
    const committed = issuedCount("commit_update_install");
    await buttons.commit.trigger("click");
    assert.equal(issuedCount("commit_update_install"), committed + 1);
    assert.deepEqual(
      invocationDetails.findLast((entry) => entry.command === "commit_update_install").args,
      { expectedVersion: "0.4.1" },
      "Install and Relaunch acts on the staged release",
    );
    assert.equal(state.updateInstall.phase, "ready");
    assert.ok(glassRoot.innerHTML.includes("(engine_stop_failed)"));
    assert.ok(glassRoot.innerHTML.includes("data-glass-update-commit>Install and Relaunch<"));

    responses.cancel_update_install = { cancelled: "staged" };
    const cancellations = issuedCount("cancel_update_install");
    await buttons.cancel.trigger("click");
    assert.equal(issuedCount("cancel_update_install"), cancellations + 1, "Cancel discards the staged release");
    assert.deepEqual(state.updateInstall, { ...IDLE_INSTALL, version: "0.4.1", ended: "cancelled" });
    assert.deepEqual(updateOffers(), NEITHER_OFFER);
    assert.equal(glassRoot.innerHTML.includes("data-glass-update-"), false);
  });
});

test("a release that failed authentication stays withdrawn through every later check", async () => {
  await withUpdateDialog(async (buttons) => {
    const verdict = { ...RELEASE, install: { supported: false, code: "release_failed_authentication" } };
    const withdrawnWith = (code, context) => {
      assert.deepEqual(updateOffers(), NEITHER_OFFER, context);
      assert.ok(
        glassRoot.innerHTML.includes(`The downloaded update is not the signed release and was discarded. Do not install it from another source. (${code})`),
        context,
      );
    };
    responses.check_for_updates = RELEASE;
    responses.prepare_update_install = () => {
      throw { code: "signature_mismatch", category: "authenticity" };
    };
    await appModule.handleAction("check-for-updates");
    assert.deepEqual(updateOffers(), BOTH_OFFERS);
    await buttons.install.trigger("click");
    withdrawnWith("signature_mismatch", "right after the failure");

    responses.check_for_updates = verdict;
    await buttons.check.trigger("click");
    withdrawnWith("signature_mismatch", "a check that carries the host's verdict");

    responses.check_for_updates = RELEASE;
    await buttons.check.trigger("click");
    withdrawnWith("signature_mismatch", "a check from the dialog");
    await emit("cfw://update-available", RELEASE);
    withdrawnWith("signature_mismatch", "the availability event");
    await appModule.handleAction("check-for-updates");
    withdrawnWith("signature_mismatch", "a check from the menu");
    const prepared = issuedCount("prepare_update_install");
    await buttons.install.trigger("click");
    assert.equal(issuedCount("prepare_update_install"), prepared, "the withdrawn installation issues no command");

    await emit("cfw://update-available", { ...RELEASE, version: "0.4.2" });
    assert.deepEqual(updateOffers(), BOTH_OFFERS, "another release is offered as usual");
    assert.ok(glassRoot.innerHTML.includes("data-glass-update-install>Install Update v0.4.2<"));

    await emit("cfw://update-available", verdict);
    assert.deepEqual(state.updateInstall, IDLE_INSTALL);
    withdrawnWith("release_failed_authentication", "the host's verdict alone, as after a reload");
  });
});

test("what the previous installation attempt left behind is logged and shown", async () => {
  await withUpdateDialog(async () => {
    const report = async (reply) => {
      responses.resolve_update_install = reply;
      await appModule.reportPreviousUpdateInstall();
      return state.logs.find((entry) => entry.source === "updater");
    };
    const interrupted = (code) => ({ outcome: { state: "failed", version: "0.4.1", code }, pending: null });

    let entry = await report(interrupted("installer_interrupted"));
    const notice = {
      title: "Update v0.4.1 was not installed",
      body: "The previous version is still installed. Reason code: installer_interrupted",
    };
    assert.deepEqual(state.glassDialog, { kind: "info", payload: notice });
    assert.ok(glassRoot.innerHTML.includes(`<h3>${notice.title}</h3>`));
    assert.ok(glassRoot.innerHTML.includes(notice.body));
    assert.deepEqual([entry.level, entry.message], ["error", `${notice.title}: ${notice.body}`]);

    for (const [rejection, reason] of [
      [
        { code: "journal_failed", category: "storage" },
        "The update could not be stored on this Mac. Free some disk space and try again. (journal_failed)",
      ],
      [
        "journal task ended",
        "The update could not be installed because of an internal error. (unexpected_error: journal task ended)",
      ],
    ]) {
      state.glassDialog = null;
      entry = await report(() => {
        throw rejection;
      });
      const body = `The previous update attempt could not be reviewed: ${reason}`;
      assert.deepEqual([entry.level, entry.message], ["error", body]);
      assert.deepEqual(state.glassDialog, { kind: "info", payload: { title: "Updates", body } });
      assert.ok(glassRoot.innerHTML.includes(body), "the reason is shown, not only logged");
    }

    state.glassDialog = null;
    entry = await report({ outcome: { state: "installed", version: "0.4.1" }, pending: null });
    assert.deepEqual([entry.level, entry.message], ["info", "Updated to v0.4.1"]);
    assert.equal(state.glassDialog, null, "a completed installation is logged only");

    const openOverlay = {
      glassDialog: () => {
        state.glassDialog = { kind: "dns-query", payload: { name: "a.test", type: "A", result: "" } };
      },
      profileContextMenu: () => {
        state.profileContextMenu = { id: PROFILE_ID, x: 10, y: 10 };
      },
      runtimeSettingsDialog: () => appModule.handleAction("open-runtime-settings"),
      automationDialog: () => appModule.handleAction("open-automation-settings"),
    };
    responses.read_automation_settings = {
      settings: { shortcuts: [], network_enabled: false, network_rules: [] },
      revision: "automation-v1", network: { kind: "wifi", interface: "en0", ssid: null },
    };
    try {
      for (const slot of OVERLAY_SLOTS) {
        for (const other of OVERLAY_SLOTS) state[other] = null;
        await openOverlay[slot]();
        const overlay = state[slot];
        assert.ok(overlay, `${slot} is open`);
        const code = `interrupted_with_${slot.toLowerCase()}_open`;
        entry = await report(interrupted(code));
        assert.deepEqual(
          [entry.level, entry.message.endsWith(`Reason code: ${code}`)], ["error", true],
          `${slot}: the failure is logged`,
        );
        assert.equal(state[slot], overlay, `${slot}: the open overlay is not replaced`);
        if (slot !== "glassDialog") assert.equal(state.glassDialog, null, `${slot}: no dialog is put over it`);
      }
    } finally {
      delete responses.read_automation_settings;
      for (const slot of OVERLAY_SLOTS) state[slot] = null;
    }

    await report({ outcome: { state: "none" }, pending: { phase: "staged", version: "0.4.1" } });
    assert.deepEqual(state.updateInstall, { ...IDLE_INSTALL, phase: "ready", version: "0.4.1" });
    assert.equal(state.glassDialog, null, "re-attaching opens nothing by itself");
    responses.check_for_updates = { available: false, current: "0.4.0" };
    await appModule.handleAction("check-for-updates");
    assert.ok(glassRoot.innerHTML.includes("v0.4.1 is ready to install."));
    assert.ok(glassRoot.innerHTML.includes("data-glass-update-commit>Install and Relaunch<"));
    assert.ok(glassRoot.innerHTML.includes("data-glass-update-cancel"));
  });
});

/// Holds back every timer the dashboard starts, so a test decides when the
/// wait between two questions about a re-attached installation elapses and no
/// real timer outlives the test.
function holdFollowWaits() {
  const setTimeoutOfWindow = globalThis.window.setTimeout;
  const waits = [];
  globalThis.window.setTimeout = (callback, delay) => waits.push({ callback, delay });
  return {
    waits,
    async elapse() {
      assert.deepEqual(waits.map(({ delay }) => delay), [1000], "exactly one wait of a second is pending");
      waits.shift().callback();
      await new Promise((resolve) => setTimeout(resolve, 20));
    },
    release() {
      globalThis.window.setTimeout = setTimeoutOfWindow;
    },
  };
}

test("a re-attached installation follows the host to its end", async () => {
  await withUpdateDialog(async (buttons) => {
    const follower = holdFollowWaits();
    const holding = (phase, outcome = { state: "none" }) => ({
      outcome, pending: phase === null ? null : { phase, version: "0.4.1" },
    });
    const reattach = async (phase) => {
      responses.resolve_update_install = holding(phase);
      await appModule.reportPreviousUpdateInstall();
    };
    try {
      responses.check_for_updates = RELEASE;
      await reattach("preparing");
      await appModule.handleAction("check-for-updates");
      assert.ok(glassRoot.innerHTML.includes('<div class="product-about-status">Downloading update…</div>'));
      assert.ok(glassRoot.innerHTML.includes("data-glass-update-cancel"));

      await follower.elapse();
      assert.deepEqual(
        state.updateInstall, { ...IDLE_INSTALL, phase: "downloading", version: "0.4.1" },
        "a preparation the host still runs is waited for",
      );

      responses.resolve_update_install = holding("staged");
      await follower.elapse();
      assert.deepEqual(state.updateInstall, { ...IDLE_INSTALL, phase: "ready", version: "0.4.1" });
      assert.ok(
        glassRoot.innerHTML.includes("data-glass-update-commit>Install and Relaunch<"),
        "the open dialog offers the staged release as soon as the host reports it",
      );
      assert.deepEqual(follower.waits, [], "a staged release is not asked about");

      responses.cancel_update_install = { cancelled: "staged" };
      await buttons.cancel.trigger("click");
      await reattach("committing");
      assert.ok(glassRoot.innerHTML.includes("Installing update… Clash for Mac will reopen automatically."));
      responses.resolve_update_install = holding(null);
      await follower.elapse();
      assert.deepEqual(state.updateInstall, { ...IDLE_INSTALL, version: "0.4.1", ended: "unreported" });
      assert.ok(glassRoot.innerHTML.includes(
        '<div class="product-about-status">The update installation is no longer in progress. Check for updates again.</div>',
      ));
      assert.deepEqual(updateOffers(), NEITHER_OFFER, "the release the lost installation consumed is not offered");
      assert.ok(glassRoot.innerHTML.includes("data-glass-check-update >Check for Update<"));
      assert.deepEqual(follower.waits, [], "nothing is asked once the host holds nothing");

      state.glassDialog = null;
      await reattach("preparing");
      const interrupted = { state: "failed", version: "0.4.0", code: "installer_start_failed" };
      responses.resolve_update_install = holding("preparing", interrupted);
      await follower.elapse();
      assert.deepEqual(state.glassDialog, {
        kind: "info",
        payload: {
          title: "Update v0.4.0 was not installed",
          body: "The previous version is still installed. Reason code: installer_start_failed",
        },
      }, "an outcome the host reports while it is followed is shown as at startup");
      assert.equal(state.updateInstall.phase, "downloading");

      state.glassDialog = null;
      responses.resolve_update_install = holding("preparing");
      await appModule.handleAction("check-for-updates");
      responses.cancel_update_install = { cancelled: "preparation" };
      await buttons.cancel.trigger("click");
      assert.deepEqual(state.updateInstall, { ...IDLE_INSTALL, version: "0.4.1", ended: "cancelled" });
      const asked = issuedCount("resolve_update_install");
      await follower.elapse();
      assert.equal(issuedCount("resolve_update_install"), asked, "nothing is asked after the user cancelled");
      assert.deepEqual(follower.waits, []);
    } finally {
      follower.release();
    }
  });
});
