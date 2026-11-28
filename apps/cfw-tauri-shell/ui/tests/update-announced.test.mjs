// An update that the host announces as a check of its own ends, as the check
// of the app menu does, which the page learns of only then. An opening of the
// download page during which one is announced may have had that update taken
// by the host, if the check ended before the host rechecked the update
// opened, or not, if it ended while the download page opened. The page cannot
// tell which, so it checks again as the opening ends, and the app offers what
// that check found, which the host holds then. An announcement that is none
// is not taken, and the opening withdraws the offer as it ends.
// support/render-harness.mjs drives the real bootstrap, so the announcement
// comes the way the host sends it.
import assert from "node:assert/strict";
import test from "node:test";
import {
  OVERLAY_SLOTS, UPDATE_COMMANDS, appModule, emit, interactiveElement, invocationDetails, page, querySelectorAllElements,
  renderPage, responses, state, waitForInvocation,
} from "./support/render-harness.mjs";

const RELEASE = Object.freeze({
  available: true, current: "0.4.0", version: "0.4.1", notes: null, date: null,
  install: { supported: false, code: "unsupported_installation" },
});
const LATER = Object.freeze({ ...RELEASE, version: "0.4.2" });

/// The host's authorization of updates as `UpdaterSecurityState` keeps it. A
/// check authorizes the release published then and announces it as it ends,
/// and one that cannot reach the releases authorizes nothing. The host takes
/// an opening up with a recheck, which takes the authorization and fails where
/// the update authorized is not the one opened; the download page then opens,
/// or fails to. `shown` has what the About dialog showed as each check of the
/// page began.
function hostUpdater() {
  const updater = { published: RELEASE, reachable: true, authorized: null, opening: null, shown: [] };
  updater.check = async () => {
    if (!updater.reachable) {
      updater.authorized = null;
      throw new Error("the releases did not answer");
    }
    const found = updater.published;
    updater.authorized = found.version;
    await emit("cfw://update-available", found);
    return found;
  };
  updater.recheck = () => {
    const { expectedVersion, reject } = updater.opening;
    const authorized = updater.authorized === expectedVersion;
    updater.authorized = null;
    if (!authorized) {
      updater.opening = null;
      reject(new Error("the presented update authorization changed"));
    }
    return authorized;
  };
  updater.open = (failure) => {
    const { expectedVersion, resolve, reject } = updater.opening;
    updater.opening = null;
    if (failure) reject(failure);
    else resolve({ opened: true, installed: false, version: expectedVersion });
  };
  responses.check_for_updates = () => {
    updater.shown.push(state.glassDialog?.kind === "product-about" ? state.glassDialog.payload.phase : null);
    return updater.check();
  };
  responses.open_available_update = ({ expectedVersion }) => new Promise((resolve, reject) => {
    updater.opening = { expectedVersion, resolve, reject };
  });
  return updater;
}

// The check of the app menu ends before the host takes the opening up, or
// while the download page opens, and a check of the page may begin while it
// opens; "none" announces nothing that is an update. Each case says what the
// app offers as the announcement has come, what it offers once the opening
// has ended, which the host holds as well, what the About dialog showed as
// each check of the page began while the opening was under way or after it,
// and what it shows once a failed opening leaves it open.
const CASES = [
  { name: "a check that ended before the host rechecked the update opened", menu: "recheck", published: LATER,
    taken: "0.4.2", offered: "0.4.2", shown: ["checking"], about: "idle 0.4.2" },
  { name: "the same, where the check made again cannot reach the releases", menu: "recheck", published: LATER, reach: false,
    taken: "0.4.2", offered: null, shown: ["checking"], about: "idle the releases did not answer" },
  { name: "a check that found the update opened before the host rechecked it", menu: "recheck", published: RELEASE,
    taken: "0.4.1", offered: "0.4.1", shown: [null], about: null },
  { name: "a check that ended while the download page opened", menu: "opening", published: LATER,
    taken: "0.4.2", offered: "0.4.2", shown: [null], about: null },
  { name: "a check that ended while the download page failed to open", menu: "opening", published: LATER, failed: true,
    taken: "0.4.2", offered: "0.4.2", shown: ["checking"], about: "idle 0.4.2" },
  { name: "a check of the page that began while the download page opened", menu: "page", published: LATER,
    taken: "0.4.2", offered: "0.4.2", shown: ["checking"], about: null },
  { name: "no check", menu: null, published: RELEASE, taken: null, offered: null, shown: [], about: null },
  { name: "no check, where the download page fails to open", menu: null, published: RELEASE, failed: true,
    taken: null, offered: null, shown: [], about: "idle no browser" },
  { name: "an announcement that is none", menu: "none", published: RELEASE, taken: "0.4.1", offered: null, shown: [], about: null },
];

/// What became of `press`: "ended", or "still waiting" where it waits for good.
const ending = (press) => Promise.race([press.then(() => "ended"),
  new Promise((resolve) => { setTimeout(resolve, 2000, "still waiting"); })]);
const made = (command) => invocationDetails.filter((entry) => entry.command === command).length;
const offer = () => (state.updateInfo?.available ? state.updateInfo.version : null);

test("an opening of the download page that ends once the host announced an update checks again, and the app offers what the host holds", async () => {
  const original = { overlays: OVERLAY_SLOTS.map((slot) => state[slot]), info: state.updateInfo, check: responses.check_for_updates };
  const open = interactiveElement();
  querySelectorAllElements.set("[data-glass-open-update]", [open]);
  const found = [];
  try {
    for (const { name, menu, published, failed = false, reach = true } of CASES) {
      for (const slot of OVERLAY_SLOTS) state[slot] = null;
      const updater = hostUpdater();
      await appModule.handleAction("check-for-updates");
      assert.equal(state.updateInfo.version, "0.4.1");
      const before = made("open_available_update");
      const checked = updater.shown.length;
      const opened = open.trigger("click");
      await waitForInvocation("open_available_update", before);
      updater.published = published;
      let taken = null;
      if (menu === "recheck") { await updater.check(); taken = offer(); }
      updater.reachable = reach;
      const rechecked = updater.recheck();
      if (menu === "opening") { await updater.check(); taken = offer(); }
      if (menu === "page") { await appModule.handleAction("check-for-updates"); taken = offer(); }
      if (menu === "none") { await emit("cfw://update-available", null); taken = offer(); }
      if (rechecked) updater.open(failed ? new Error("no browser") : null);
      const ended = await ending(opened);
      const dialog = state.glassDialog?.kind === "product-about" ? state.glassDialog.payload : null;
      found.push({
        name, ended, taken, offered: offer(), held: updater.authorized, shown: updater.shown.slice(checked),
        about: dialog && [dialog.phase, dialog.update?.version, dialog.update?.error].filter(Boolean).join(" "),
      });
    }
  } finally {
    for (const command of UPDATE_COMMANDS) delete responses[command];
    responses.check_for_updates = original.check;
    querySelectorAllElements.clear();
    OVERLAY_SLOTS.forEach((slot, index) => { state[slot] = original.overlays[index]; });
    state.updateInfo = original.info;
  }
  assert.deepEqual(found, CASES.map(({ name, taken, offered, shown, about }) => ({
    name, ended: "ended", taken, offered, held: offered, shown, about,
  })));
});

test("an update announced, and a check made again that cannot reach the releases, draw the pages that show the offer and no other", async () => {
  const original = { overlays: OVERLAY_SLOTS.map((slot) => state[slot]), info: state.updateInfo, check: responses.check_for_updates,
    page: state.activePage };
  const open = interactiveElement();
  querySelectorAllElements.set("[data-glass-open-update]", [open]);
  const found = {};
  try {
    for (const shown of ["general", "feedback", "profiles", "settings"]) {
      for (const slot of OVERLAY_SLOTS) state[slot] = null;
      await renderPage(shown);
      const updater = hostUpdater();
      await appModule.handleAction("check-for-updates");
      const before = made("open_available_update");
      const opened = open.trigger("click");
      await waitForInvocation("open_available_update", before);
      updater.published = LATER;
      // What the announcement and the failure leave drawn is theirs alone.
      page.innerHTML = "untouched";
      await updater.check();
      const announced = page.innerHTML;
      page.innerHTML = "untouched";
      updater.reachable = false;
      updater.recheck();
      const ended = await ending(opened);
      found[shown] = { ended, offered: offer(), announced, drawn: page.innerHTML };
    }
  } finally {
    for (const command of UPDATE_COMMANDS) delete responses[command];
    responses.check_for_updates = original.check;
    querySelectorAllElements.clear();
    OVERLAY_SLOTS.forEach((slot, index) => { state[slot] = original.overlays[index]; });
    state.updateInfo = original.info;
    await renderPage(original.page);
  }
  for (const [shown, { ended, offered }] of Object.entries(found)) assert.deepEqual([ended, offered], ["ended", null], shown);
  const { general, feedback, profiles, settings } = found;
  assert.match(general.announced, /cfw-update-badge[^]*v0\.4\.2/u, "the announcement drew General with the offer");
  assert.match(feedback.announced, /v0\.4\.2/u, "and the About page");
  assert.notEqual(general.drawn, "untouched", "the failure of the check made again drew General");
  assert.doesNotMatch(general.drawn, /cfw-update-badge/u, "without the offer it withdrew");
  assert.notEqual(feedback.drawn, "untouched", "and the About page");
  assert.doesNotMatch(feedback.drawn, /v0\.4\.2/u, "without the offer either");
  for (const [name, { announced, drawn }] of [["Profiles", profiles], ["Settings", settings]]) {
    assert.deepEqual([announced, drawn], ["untouched", "untouched"], `neither drew ${name}, which does not show the offer`);
  }
});
