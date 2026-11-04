// Installing a staged release and what the previous attempt left behind: the
// hand-off that commits only a staged release, and the outcome the host
// reports, unreadable or outside its contract.
import assert from "node:assert/strict";
import { t } from "../src/i18n.js";
import { IDLE_UPDATE_INSTALL } from "../src/update-install.js";
import {
  CANCELLED, CANCELLED_LOG, NEWER, NOTHING_HELD, READY, UNEXPECTED, failed, failure, harness,
  macFailureText, resolution, test, withdrawn,
} from "./support/update-install-harness.mjs";

test("installing commits only a staged release and returns to it when the hand-off fails", async () => {
  const idle = harness({ commit_update_install: { version: "0.5.0" } });
  await idle.install.commit();
  assert.deepEqual(idle.invoked, [], "nothing is committed before a release is staged");

  const started = harness({ commit_update_install: { version: "0.5.0" } });
  started.state.updateInstall = { ...READY };
  await started.install.commit();
  assert.deepEqual(started.invoked, [["commit_update_install", { expectedVersion: "0.5.0" }]]);
  assert.equal(started.state.updateInstall.phase, "installing");

  const superseded = harness({ commit_update_install: { version: "0.5.0" } });
  superseded.state.updateInfo = { ...NEWER };
  superseded.state.updateInstall = { ...READY };
  await superseded.install.commit();
  assert.deepEqual(
    superseded.invoked, [["commit_update_install", { expectedVersion: "0.5.0" }]],
    "the staged release is installed, whatever a later check presented",
  );

  const stopFailed = failure("engine_stop_failed", "engine");
  const busy = harness({ commit_update_install: { reject: stopFailed } });
  busy.state.updateInstall = { ...READY };
  await busy.install.commit();
  assert.deepEqual(
    busy.state.updateInstall, { ...READY, failure: stopFailed },
    "the verified release stays staged for another attempt",
  );
  assert.deepEqual(busy.view().primary, { action: "commit", label: t("Install and Relaunch") });
  assert.equal(busy.view().status, macFailureText(stopFailed));
  assert.deepEqual(busy.logs, [
    ["error", "updater", t("Update not installed: {reason}", { reason: macFailureText(stopFailed) })],
  ]);

  const missing = failure("no_staged_update", "state");
  const gone = harness({ commit_update_install: { reject: missing } });
  gone.state.updateInstall = { ...READY };
  await gone.install.commit();
  assert.deepEqual(gone.state.updateInstall, failed(missing));
  assert.deepEqual(
    gone.view(), withdrawn(macFailureText(missing)),
    "a release the host no longer holds is offered neither for installation nor for download",
  );
});

test("a hand-off that fails after the host discarded the release does not restore it", async () => {
  const raced = harness();
  raced.state.updateInstall = { ...READY };
  const cancelling = raced.install.cancel();
  const committing = raced.install.commit();
  assert.equal(raced.state.updateInstall.phase, "installing");
  raced.pending.get("cancel_update_install").resolve({ cancelled: "staged" });
  await cancelling;
  assert.deepEqual(raced.state.updateInstall, CANCELLED);
  const active = failure("install_already_active", "busy");
  raced.pending.get("commit_update_install").reject(active);
  await committing;
  assert.deepEqual(raced.state.updateInstall, CANCELLED);
  assert.deepEqual(raced.logs, [
    CANCELLED_LOG,
    ["error", "updater", t("Update not installed: {reason}", { reason: macFailureText(active) })],
  ]);
});

test("the outcome of the previous attempt is logged and a failure is shown", async () => {
  const none = harness({ resolve_update_install: NOTHING_HELD });
  await none.install.resolveOutcome();
  assert.deepEqual(none.invoked, [["resolve_update_install", undefined]]);
  assert.deepEqual(none.logs, []);
  assert.deepEqual(none.notices, []);
  assert.deepEqual(none.state.updateInstall, IDLE_UPDATE_INSTALL);
  assert.deepEqual(none.naps, [], "nothing is held that would have to be asked about");

  const installed = harness({ resolve_update_install: resolution({ state: "installed", version: "0.5.0" }) });
  await installed.install.resolveOutcome();
  assert.deepEqual(installed.logs, [["info", "updater", t("Updated to v{version}", { version: "0.5.0" })]]);
  assert.deepEqual(installed.notices, []);

  const interrupted = harness({
    resolve_update_install: resolution({ state: "failed", version: "0.5.0", code: "application_reopened" }),
  });
  await interrupted.install.resolveOutcome();
  const notice = {
    title: t("Update v{version} was not installed", { version: "0.5.0" }),
    body: t("The previous version is still installed. Reason code: {code}", { code: "application_reopened" }),
  };
  assert.deepEqual(interrupted.notices, [notice]);
  assert.deepEqual(interrupted.logs, [["error", "updater", `${notice.title}: ${notice.body}`]]);
});

test("a previous attempt that could not be reviewed is logged and shown with its reason", async () => {
  const journal = failure("journal_failed", "storage");
  for (const [rejection, reason] of [
    [journal, macFailureText(journal)],
    ["journal task ended", macFailureText(UNEXPECTED, "journal task ended")],
    [new Error("bridge closed"), macFailureText(UNEXPECTED, "bridge closed")],
  ]) {
    const unavailable = harness({ resolve_update_install: { reject: rejection } });
    const body = t("The previous update attempt could not be reviewed: {reason}", { reason });
    await unavailable.install.resolveOutcome();
    assert.deepEqual(unavailable.notices, [{ title: t("Updates"), body }]);
    assert.deepEqual(unavailable.logs, [["error", "updater", body]]);
    assert.deepEqual(unavailable.state.updateInstall, IDLE_UPDATE_INSTALL);
    assert.deepEqual(unavailable.naps, []);
  }
  assert.ok(macFailureText(journal).endsWith("(journal_failed)"));
});

test("a reply about the previous attempt outside the contract is a defect, not an absent record", async () => {
  const staged = { phase: "staged", version: "0.5.0" };
  for (const reply of [
    null,
    {},
    { state: "none" },
    { state: "failed", version: "0.5.0", code: "application_reopened" },
    { outcome: { state: "none" } },
    { outcome: { state: "installed" }, pending: null },
    { outcome: { state: "failed", version: "0.5.0" }, pending: null },
    { outcome: { state: "unknown" }, pending: staged },
    { outcome: { state: "none" }, pending: { phase: "ready", version: "0.5.0" } },
    { outcome: { state: "none" }, pending: { phase: "staged" } },
    { outcome: { state: "none" }, pending: { phase: ["staged"], version: "0.5.0" } },
    { outcome: { state: "none" }, pending: "staged" },
  ]) {
    const malformed = harness({ resolve_update_install: reply });
    const body = t("The previous update attempt could not be reviewed: {reason}", {
      reason: macFailureText(UNEXPECTED, "resolve_update_install returned an unexpected reply"),
    });
    await malformed.install.resolveOutcome();
    assert.deepEqual(malformed.notices, [{ title: t("Updates"), body }], JSON.stringify(reply));
    assert.deepEqual(malformed.logs, [["error", "updater", body]], JSON.stringify(reply));
    assert.deepEqual(
      malformed.state.updateInstall, IDLE_UPDATE_INSTALL,
      `nothing is re-attached from ${JSON.stringify(reply)}`,
    );
    assert.deepEqual(malformed.naps, [], JSON.stringify(reply));
  }
});
