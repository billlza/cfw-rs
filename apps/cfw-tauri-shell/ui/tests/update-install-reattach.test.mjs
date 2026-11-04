// An installation the host still holds after a reload: re-attaching to it,
// following it to its end, and the questions the host refuses or answers after
// the view has moved on.
import assert from "node:assert/strict";
import { t } from "../src/i18n.js";
import { IDLE_UPDATE_INSTALL, installAfterCheck } from "../src/update-install.js";
import {
  ATTACHED, CANCELLED, CANCELLED_LOG, NETWORK, NOTHING_HELD, UNEXPECTED, UPDATE, answers, failed,
  failure, harness, held, macFailureText, resolution, settled, test, unread, withdrawn,
} from "./support/update-install-harness.mjs";

test("an installation the host still holds is re-attached after a reload", async () => {
  for (const [phase, shown, asked] of [
    ["preparing", "downloading", [1000]],
    ["staged", "ready", []],
    ["committing", "installing", [1000]],
  ]) {
    const { state, install, logs, notices, naps } = harness({ resolve_update_install: held(phase) });
    state.updateInfo = null;
    await install.resolveOutcome();
    assert.deepEqual(state.updateInstall, { ...IDLE_UPDATE_INSTALL, phase: shown, version: "0.4.9" }, phase);
    assert.deepEqual(logs, [], phase);
    assert.deepEqual(notices, [], phase);
    assert.deepEqual(
      naps.map(({ milliseconds }) => milliseconds), asked,
      `${phase}: only an installation that is running is asked about, a second later`,
    );
  }

  const untouched = harness({ resolve_update_install: NOTHING_HELD });
  untouched.state.updateInstall = failed(NETWORK);
  const before = untouched.state.updateInstall;
  await untouched.install.resolveOutcome();
  assert.equal(untouched.state.updateInstall, before, "without a held installation nothing changes");
  assert.equal(untouched.changes(), 0);

  const both = harness({
    resolve_update_install: resolution(
      { state: "failed", version: "0.4.8", code: "installer_interrupted" },
      { phase: "staged", version: "0.4.9" },
    ),
  });
  await both.install.resolveOutcome();
  assert.equal(both.notices.length, 1);
  assert.equal(both.state.updateInstall.phase, "ready", "a held installation is re-attached beside a reported failure");
});

test("a re-attached installation is shown and acted on like one this page started", async () => {
  const preparing = harness({
    resolve_update_install: held("preparing"),
    cancel_update_install: { cancelled: "preparation" },
  });
  preparing.state.updateInfo = null;
  await preparing.install.resolveOutcome();
  preparing.install.onProgress({ phase: "downloading", version: "0.4.9", downloaded: 5, total: 10 });
  assert.equal(preparing.view().status, t("Downloading update… {percent}%", { percent: 50 }));
  preparing.install.onProgress({ phase: "verifying", version: "0.4.9" });
  assert.equal(preparing.state.updateInstall.phase, "verifying");
  await preparing.install.cancel();
  assert.deepEqual(
    preparing.state.updateInstall, { ...CANCELLED, version: "0.4.9" },
    "no reply is left that could end a re-attached preparation",
  );
  assert.deepEqual(preparing.logs, [CANCELLED_LOG]);

  const staged = harness({
    resolve_update_install: held("staged"),
    commit_update_install: { version: "0.4.9" },
  });
  staged.state.updateInfo = null;
  await staged.install.resolveOutcome();
  assert.deepEqual(staged.view().primary, { action: "commit", label: t("Install and Relaunch") });
  await staged.install.commit();
  assert.deepEqual(staged.invoked.at(-1), ["commit_update_install", { expectedVersion: "0.4.9" }]);
});

test("an installation this page started is never asked about", async () => {
  const { state, install, naps } = harness({ resolve_update_install: held("preparing", "0.5.0") });
  void install.prepare();
  install.onProgress({ phase: "downloading", version: "0.5.0", downloaded: 10, total: 40 });
  const started = state.updateInstall;
  await install.resolveOutcome();
  assert.equal(state.updateInstall, started, "it keeps its own progress");
  assert.deepEqual(naps, [], "and is followed through its own replies");
});

test("the page's own preparation is not mistaken for one it had re-attached", async () => {
  const { state, install, naps, issued, elapse } = harness({
    resolve_update_install: answers(held("preparing", "0.5.0")),
    cancel_update_install: { cancelled: "preparation" },
  });
  await install.resolveOutcome();
  await install.cancel();
  state.updateInstall = installAfterCheck(state.updateInstall, state.updateInfo);
  void install.prepare();
  assert.deepEqual(state.updateInstall, { ...ATTACHED, version: "0.5.0" });
  await elapse();
  assert.equal(issued("resolve_update_install"), 1, "the same release in the same phase is still not asked about");
  assert.deepEqual(naps, []);
});

test("a re-attached preparation is followed until the host has staged the release", async () => {
  const { state, install, logs, naps, issued, elapse } = harness({
    resolve_update_install: answers(held("preparing"), held("preparing"), held("staged")),
  });
  state.updateInfo = null;
  await install.resolveOutcome();
  assert.equal(issued("resolve_update_install"), 1);

  install.onProgress({ phase: "downloading", version: "0.4.9", downloaded: 5, total: 10 });
  install.onProgress({ phase: "verifying", version: "0.4.9" });
  const verifying = state.updateInstall;
  await elapse();
  assert.equal(issued("resolve_update_install"), 2);
  assert.equal(state.updateInstall, verifying, "a preparation that is still running keeps its progress");
  assert.deepEqual(naps.map(({ milliseconds }) => milliseconds), [1000], "and is asked about again a second later");
  assert.deepEqual(logs, []);

  await elapse();
  assert.equal(issued("resolve_update_install"), 3);
  assert.deepEqual(state.updateInstall, { ...IDLE_UPDATE_INSTALL, phase: "ready", version: "0.4.9" });
  assert.deepEqual(logs, [
    ["info", "updater", t("Update v{version} is verified and ready to install", { version: "0.4.9" })],
  ]);
  assert.deepEqual(naps, [], "a staged release waits for the user and is not asked about");
});

test("a re-attached hand-off that did not start leaves the release staged", async () => {
  const { state, install, view, invoked, naps, elapse } = harness({
    resolve_update_install: answers(held("committing"), held("committing"), held("staged")),
    commit_update_install: { version: "0.4.9" },
  });
  state.updateInfo = null;
  await install.resolveOutcome();
  const installing = state.updateInstall;
  await elapse();
  assert.equal(state.updateInstall, installing, "a hand-off that is still running is waited for");
  await elapse();
  assert.deepEqual(state.updateInstall, { ...IDLE_UPDATE_INSTALL, phase: "ready", version: "0.4.9" });
  assert.deepEqual(view().primary, { action: "commit", label: t("Install and Relaunch") });
  assert.deepEqual(naps, []);
  await install.commit();
  assert.deepEqual(invoked.at(-1), ["commit_update_install", { expectedVersion: "0.4.9" }]);
});

test("an installation the host no longer holds ends the view and needs a fresh check", async () => {
  const sentence = t("The update installation is no longer in progress. Check for updates again.");
  for (const phase of ["preparing", "committing"]) {
    const { state, install, view, logs, naps, issued, elapse } = harness({
      resolve_update_install: answers(held(phase), NOTHING_HELD),
    });
    await install.resolveOutcome();
    await elapse();
    assert.deepEqual(state.updateInstall, { ...IDLE_UPDATE_INSTALL, version: "0.4.9", ended: "unreported" }, phase);
    assert.deepEqual(view(), withdrawn(sentence), phase);
    assert.deepEqual(logs, [["warning", "updater", sentence]], phase);
    assert.deepEqual(naps, [], phase);
    assert.equal(issued("resolve_update_install"), 2, phase);
    assert.deepEqual(installAfterCheck(state.updateInstall, UPDATE), IDLE_UPDATE_INSTALL, phase);
  }
});

const JOURNAL = failure("journal_failed", "storage");

const REFUSED_LOG = unread(macFailureText(JOURNAL));

const MALFORMED_LOG = unread(macFailureText(UNEXPECTED, "resolve_update_install returned an unexpected reply"));

test("a question the host refuses is logged with its code and asked again until it is answered", async () => {
  const { state, install, logs, naps, issued, elapse } = harness({
    resolve_update_install: answers(held("preparing"), { reject: JOURNAL }, held("staged")),
  });
  await install.resolveOutcome();
  await elapse();
  assert.deepEqual(logs, [REFUSED_LOG]);
  assert.ok(REFUSED_LOG[2].endsWith("(journal_failed)"));
  assert.deepEqual(state.updateInstall, ATTACHED, "the view keeps the installation meanwhile");
  await elapse();
  assert.equal(state.updateInstall.phase, "ready", "asking went on until the host answered");
  assert.equal(issued("resolve_update_install"), 3);
  assert.deepEqual(naps, []);
});

test("the same refusal is logged once while the host repeats it", async () => {
  const { state, install, logs, elapse } = harness({
    resolve_update_install: answers(
      held("preparing"), { reject: JOURNAL }, { reject: JOURNAL }, { reject: JOURNAL }, { outcome: { state: "none" } },
    ),
  });
  await install.resolveOutcome();
  await elapse();
  await elapse();
  await elapse();
  assert.deepEqual(logs, [REFUSED_LOG]);
  await elapse();
  assert.deepEqual(logs, [REFUSED_LOG, MALFORMED_LOG], "a reply outside the contract is another refusal");
  assert.deepEqual(state.updateInstall, ATTACHED);
});

test("a refusal after an answer is logged again", async () => {
  const { install, logs, elapse } = harness({
    resolve_update_install: answers(held("preparing"), { reject: JOURNAL }, held("preparing"), { reject: JOURNAL }),
  });
  await install.resolveOutcome();
  await elapse();
  await elapse();
  assert.deepEqual(logs, [REFUSED_LOG], "an answer is nothing to log");
  await elapse();
  assert.deepEqual(logs, [REFUSED_LOG, REFUSED_LOG]);
});

test("the wait that was pending asks nothing once the view has left the installation", async () => {
  const { state, install, naps, issued, elapse } = harness({
    resolve_update_install: answers(held("preparing")),
    cancel_update_install: { cancelled: "preparation" },
  });
  await install.resolveOutcome();
  await install.cancel();
  assert.deepEqual(state.updateInstall, { ...CANCELLED, version: "0.4.9" });
  await elapse();
  assert.equal(issued("resolve_update_install"), 1);
  assert.deepEqual(naps, []);
});

test("nothing is asked once the view no longer shows the installation, whoever changed it", async () => {
  const { state, install, naps, issued, elapse } = harness({
    resolve_update_install: answers(held("committing")),
  });
  await install.resolveOutcome();
  state.updateInstall = { ...IDLE_UPDATE_INSTALL };
  await elapse();
  assert.equal(issued("resolve_update_install"), 1);
  assert.deepEqual(naps, []);
  assert.deepEqual(state.updateInstall, IDLE_UPDATE_INSTALL);
});

test("an answer about an installation the view has left changes nothing", async () => {
  const { state, install, logs, naps, pending, issued, elapse } = harness({
    resolve_update_install: answers(held("preparing")),
    cancel_update_install: { cancelled: "preparation" },
  });
  await install.resolveOutcome();
  await elapse();
  assert.equal(issued("resolve_update_install"), 2);
  assert.deepEqual(naps, [], "one question at a time: none is prepared before the host has answered");
  await install.cancel();
  pending.get("resolve_update_install").resolve(held("staged"));
  await settled();
  assert.deepEqual(state.updateInstall, { ...CANCELLED, version: "0.4.9" });
  assert.deepEqual(logs, [CANCELLED_LOG]);
  assert.deepEqual(naps, []);
  assert.equal(issued("resolve_update_install"), 2);
});

const INTERRUPTED = Object.freeze({ state: "failed", version: "0.4.8", code: "installer_interrupted" });

const INTERRUPTED_NOTICE = Object.freeze({
  title: t("Update v{version} was not installed", { version: "0.4.8" }),
  body: t("The previous version is still installed. Reason code: {code}", { code: "installer_interrupted" }),
});

test("what the previous attempt left behind is reported the same way while following", async () => {
  const { state, install, logs, notices, naps, elapse } = harness({
    resolve_update_install: answers(
      held("preparing"),
      resolution(INTERRUPTED, { phase: "preparing", version: "0.4.9" }),
      resolution({ state: "installed", version: "0.4.9" }, { phase: "preparing", version: "0.4.9" }),
    ),
  });
  await install.resolveOutcome();
  await elapse();
  assert.deepEqual(notices, [INTERRUPTED_NOTICE]);
  assert.deepEqual(logs, [["error", "updater", `${INTERRUPTED_NOTICE.title}: ${INTERRUPTED_NOTICE.body}`]]);
  await elapse();
  assert.deepEqual(logs.at(-1), ["info", "updater", t("Updated to v{version}", { version: "0.4.9" })]);
  assert.deepEqual(notices, [INTERRUPTED_NOTICE]);
  assert.deepEqual(state.updateInstall, ATTACHED, "the installation is followed on");
  assert.equal(naps.length, 1);
});

test("an outcome is reported even when its answer comes too late for the view", async () => {
  const { state, install, notices, naps, pending, elapse } = harness({
    resolve_update_install: answers(held("preparing")),
    cancel_update_install: { cancelled: "preparation" },
  });
  await install.resolveOutcome();
  await elapse();
  await install.cancel();
  pending.get("resolve_update_install").resolve(resolution(INTERRUPTED, { phase: "staged", version: "0.4.9" }));
  await settled();
  assert.deepEqual(notices, [INTERRUPTED_NOTICE]);
  assert.deepEqual(state.updateInstall, { ...CANCELLED, version: "0.4.9" });
  assert.deepEqual(naps, []);
});

test("the view follows whatever running installation the host reports", async () => {
  const { state, install, issued, elapse } = harness({
    resolve_update_install: answers(held("preparing"), held("committing"), held("preparing", "0.5.0"), NOTHING_HELD),
  });
  await install.resolveOutcome();
  install.onProgress({ phase: "downloading", version: "0.4.9", downloaded: 5, total: 10 });
  await elapse();
  assert.deepEqual(state.updateInstall, { ...IDLE_UPDATE_INSTALL, phase: "installing", version: "0.4.9" });
  await elapse();
  assert.deepEqual(state.updateInstall, { ...ATTACHED, version: "0.5.0" });
  await elapse();
  assert.deepEqual(state.updateInstall, { ...IDLE_UPDATE_INSTALL, version: "0.5.0", ended: "unreported" });
  assert.equal(issued("resolve_update_install"), 4, "one question at a time, whichever installation is followed");
});
