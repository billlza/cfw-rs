// Preparing and cancelling an in-app installation: one command per offered
// action, host progress, failed and cancelled preparations, discarded
// releases, and cancellations the host confirms, refuses or answers late.
import assert from "node:assert/strict";
import { t } from "../src/i18n.js";
import { IDLE_UPDATE_INSTALL, installAfterCheck } from "../src/update-install.js";
import {
  CANCELLED, CANCELLED_LOG, INSTALL_OFFER, NETWORK, NETWORK_LOG, NOTHING_PRESENTED, READY,
  READY_LOG, TOO_LATE, UNAUTHENTIC, UNEXPECTED, UPDATE, answers, failed, failure, harness, held,
  macFailureText, test, withdrawn,
} from "./support/update-install-harness.mjs";

test("an action the view does not offer issues no command", async () => {
  const cases = [
    ["a copy that cannot replace itself", { updateInfo: { ...UPDATE, install: { supported: false, code: "not_in_applications" } } }],
    ["nothing presented", { updateInfo: { ...NOTHING_PRESENTED } }],
    ["no check yet", { updateInfo: null }],
    ["a release that failed authentication", { updateInfo: { ...UNAUTHENTIC } }],
    ["a failed attempt", { updateInstall: failed(NETWORK) }],
    ["a cancelled attempt", { updateInstall: { ...CANCELLED } }],
  ];
  // Every command is answered, so an action that is wrongly issued is
  // reported by the assertion instead of leaving the test waiting.
  const answering = () => harness({
    prepare_update_install: { version: "0.5.0" },
    commit_update_install: { version: "0.5.0" },
    cancel_update_install: { cancelled: "nothing" },
  });
  for (const [name, presented] of cases) {
    const { state, invoked, install } = answering();
    Object.assign(state, presented);
    await install.prepare();
    await install.commit();
    await install.cancel();
    assert.deepEqual(invoked, [], name);
  }

  const installing = answering();
  installing.state.updateInstall = { ...READY, phase: "installing" };
  await installing.install.prepare();
  await installing.install.commit();
  await installing.install.cancel();
  assert.deepEqual(installing.invoked, [], "nothing is left to ask for once the hand-off has begun");
});

test("preparing issues one command for the presented release and follows host progress", async () => {
  const { state, invoked, pending, install, logs, changes } = harness();
  const preparing = install.prepare();
  assert.deepEqual(invoked, [["prepare_update_install", { expectedVersion: "0.5.0" }]]);
  assert.equal(state.updateInstall.phase, "downloading");
  void install.prepare();
  assert.equal(invoked.length, 1, "a second request while one is running issues no command");

  install.onProgress({ phase: "downloading", version: "0.5.0", downloaded: 10, total: 40 });
  assert.deepEqual(
    [state.updateInstall.downloaded, state.updateInstall.total],
    [10, 40],
  );
  const rendered = changes();
  install.onProgress({ phase: "downloading", version: "0.4.9", downloaded: 39, total: 40 });
  assert.equal(changes(), rendered, "progress of another release changes nothing");
  install.onProgress({ phase: "downloading", version: "0.5.0", downloaded: "39", total: -1 });
  assert.deepEqual(
    [state.updateInstall.downloaded, state.updateInstall.total],
    [0, null],
    "malformed counters are shown as an unknown amount",
  );
  install.onProgress({ phase: "verifying", version: "0.5.0" });
  assert.equal(state.updateInstall.phase, "verifying");
  install.onProgress({ phase: "ready", version: "0.5.0" });
  assert.equal(state.updateInstall.phase, "verifying", "only the command reply stages the release");

  pending.get("prepare_update_install").resolve({ version: "0.5.0" });
  await preparing;
  assert.equal(state.updateInstall.phase, "ready");
  assert.equal(state.updateInstall.failure, null);
  assert.deepEqual(logs, [READY_LOG]);
  install.onProgress({ phase: "downloading", version: "0.5.0", downloaded: 1, total: 2 });
  assert.equal(state.updateInstall.phase, "ready", "late progress never unstages a release");
});

test("a failed preparation is shown and logged, a cancelled one is not an error", async () => {
  const forged = failure("signature_mismatch", "authenticity");
  const rejected = harness({ prepare_update_install: { reject: forged } });
  await rejected.install.prepare();
  assert.deepEqual(rejected.state.updateInstall, failed(forged));
  assert.deepEqual(rejected.logs, [
    ["error", "updater", t("Update not installed: {reason}", { reason: macFailureText(forged) })],
  ]);

  const cancelled = harness({ prepare_update_install: { reject: failure("download_cancelled", "state") } });
  await cancelled.install.prepare();
  assert.deepEqual(cancelled.state.updateInstall, CANCELLED);
  assert.deepEqual(cancelled.logs, [CANCELLED_LOG]);

  for (const [rejection, text] of [
    [new Error("bridge closed"), "bridge closed"],
    ["command unavailable", "command unavailable"],
  ]) {
    const unstructured = harness({ prepare_update_install: { reject: rejection } });
    await unstructured.install.prepare();
    assert.deepEqual(unstructured.state.updateInstall, failed(UNEXPECTED));
    assert.deepEqual(unstructured.logs, [
      ["error", "updater", t("Update not installed: {reason}", { reason: macFailureText(UNEXPECTED, text) })],
    ]);
    assert.ok(
      unstructured.logs[0][2].includes(text),
      "a rejection the host does not define keeps its own text in the log",
    );
  }
});

test("a consumed release is prepared again only after a fresh check", async () => {
  for (const ending of [NETWORK, failure("download_cancelled", "state")]) {
    const { state, invoked, pending, install, view } = harness();
    const first = install.prepare();
    pending.get("prepare_update_install").reject(ending);
    await first;
    assert.equal(view().primary, null, ending.code);
    assert.equal(view().offerDownloadPage, false, ending.code);
    void install.prepare();
    assert.equal(invoked.length, 1, `${ending.code}: the consumed release is not prepared again`);

    state.updateInstall = installAfterCheck(state.updateInstall, state.updateInfo);
    assert.deepEqual(view().primary, INSTALL_OFFER, ending.code);
    assert.equal(view().offerDownloadPage, true, ending.code);
    void install.prepare();
    assert.deepEqual(invoked.at(-1), ["prepare_update_install", { expectedVersion: "0.5.0" }]);
    assert.equal(invoked.length, 2, ending.code);
  }
});

test("there is nothing to cancel before an installation has begun", async () => {
  const idle = harness({ cancel_update_install: { cancelled: "nothing" } });
  await idle.install.cancel();
  assert.deepEqual(idle.invoked, []);
  assert.deepEqual(idle.state.updateInstall, IDLE_UPDATE_INSTALL);
});

test("a cancelled preparation ends through its own reply", async () => {
  const running = harness({ cancel_update_install: { cancelled: "preparation" } });
  const preparing = running.install.prepare();
  await running.install.cancel();
  assert.deepEqual(running.invoked.at(-1), ["cancel_update_install", undefined]);
  assert.equal(running.state.updateInstall.phase, "downloading", "the host has only told the preparation to stop");
  assert.deepEqual(running.logs, [], "nothing is reported before the preparation has ended");
  running.pending.get("prepare_update_install").reject(failure("download_cancelled", "state"));
  await preparing;
  assert.deepEqual(running.state.updateInstall, CANCELLED);
  assert.deepEqual(running.logs, [CANCELLED_LOG]);
});

test("a staged release is gone once the host has discarded it or holds nothing", async () => {
  for (const held of ["staged", "nothing"]) {
    const staged = harness({ cancel_update_install: { cancelled: held } });
    staged.state.updateInstall = { ...READY };
    await staged.install.cancel();
    assert.deepEqual(staged.state.updateInstall, CANCELLED, held);
    assert.deepEqual(staged.logs, [CANCELLED_LOG], held);
    assert.deepEqual(staged.view(), withdrawn(t("Update download cancelled")), held);
  }
});

test("a release the host staged and then discarded never becomes ready", async () => {
  const { state, logs, pending, install, issued } = harness({
    cancel_update_install: answers({ cancelled: "staged" }, { cancelled: "nothing" }),
  });
  const preparing = install.prepare();
  install.onProgress({ phase: "verifying", version: "0.5.0" });
  await install.cancel();
  assert.deepEqual(state.updateInstall, CANCELLED);
  pending.get("prepare_update_install").resolve({ version: "0.5.0" });
  await preparing;
  assert.deepEqual(state.updateInstall, CANCELLED, "the late reply of the preparation stages nothing");
  assert.deepEqual(logs, [CANCELLED_LOG]);
  void install.commit();
  assert.equal(issued("commit_update_install"), 0);
});

test("a release staged after this page stopped waiting for it is discarded on the host", async () => {
  const { state, logs, pending, install, issued } = harness({
    cancel_update_install: answers({ cancelled: "nothing" }, { cancelled: "staged" }),
  });
  const preparing = install.prepare();
  await install.cancel();
  assert.deepEqual(state.updateInstall, CANCELLED);
  assert.equal(issued("cancel_update_install"), 1);
  pending.get("prepare_update_install").resolve({ version: "0.5.0" });
  await preparing;
  assert.equal(issued("cancel_update_install"), 2, "the host is told to discard what no view shows");
  assert.deepEqual(state.updateInstall, CANCELLED);
  assert.deepEqual(logs, [CANCELLED_LOG]);
});

test("a refused discard of a release no view shows is logged", async () => {
  for (const [refusal, reason] of [
    [{ reject: TOO_LATE }, macFailureText(TOO_LATE)],
    [{ cancelled: true }, macFailureText(UNEXPECTED, "cancel_update_install returned an unexpected reply")],
  ]) {
    const { state, logs, pending, install } = harness({
      cancel_update_install: answers({ cancelled: "nothing" }, refusal),
    });
    const preparing = install.prepare();
    await install.cancel();
    pending.get("prepare_update_install").resolve({ version: "0.5.0" });
    await preparing;
    assert.deepEqual(logs, [
      CANCELLED_LOG,
      ["error", "updater", t("Update not cancelled: {reason}", { reason })],
    ], JSON.stringify(refusal));
    assert.deepEqual(state.updateInstall, CANCELLED, JSON.stringify(refusal));
  }
});

test("a cancellation confirmed after the release was staged discards it", async () => {
  const { state, logs, pending, install } = harness();
  const preparing = install.prepare();
  install.onProgress({ phase: "verifying", version: "0.5.0" });
  const cancelling = install.cancel();
  pending.get("prepare_update_install").resolve({ version: "0.5.0" });
  await preparing;
  assert.equal(state.updateInstall.phase, "ready");
  pending.get("cancel_update_install").resolve({ cancelled: "staged" });
  await cancelling;
  assert.deepEqual(state.updateInstall, CANCELLED, "the reply decides, not the phase in which Cancel was pressed");
  assert.deepEqual(logs, [READY_LOG, CANCELLED_LOG]);
});

test("a cancellation that finds nothing ends the view and a late failure is only logged", async () => {
  const { state, logs, pending, install, issued } = harness({ cancel_update_install: { cancelled: "nothing" } });
  const preparing = install.prepare();
  await install.cancel();
  assert.deepEqual(state.updateInstall, CANCELLED);
  pending.get("prepare_update_install").reject(NETWORK);
  await preparing;
  assert.deepEqual(state.updateInstall, CANCELLED, "a late failure does not reopen an ended view");
  assert.deepEqual(logs, [CANCELLED_LOG, NETWORK_LOG], "the late failure is still logged");
  assert.equal(issued("cancel_update_install"), 1, "a failed preparation staged nothing the host would have to discard");
});

test("one cancellation is reported once", async () => {
  const { state, logs, pending, install, issued } = harness({ cancel_update_install: { cancelled: "nothing" } });
  const preparing = install.prepare();
  await install.cancel();
  pending.get("prepare_update_install").reject(failure("download_cancelled", "state"));
  await preparing;
  assert.deepEqual(logs, [CANCELLED_LOG]);
  assert.deepEqual(state.updateInstall, CANCELLED);
  assert.equal(issued("cancel_update_install"), 1, "a cancelled preparation staged nothing either");
});

test("a cancellation that finds the attempt already ended keeps its reason", async () => {
  const { state, logs, pending, install } = harness();
  const preparing = install.prepare();
  const cancelling = install.cancel();
  pending.get("prepare_update_install").reject(NETWORK);
  await preparing;
  pending.get("cancel_update_install").resolve({ cancelled: "nothing" });
  await cancelling;
  assert.deepEqual(state.updateInstall, failed(NETWORK));
  assert.deepEqual(logs, [NETWORK_LOG]);
});

test("a refused cancellation changes nothing but the reported reason", async () => {
  const refused = harness({ cancel_update_install: { reject: TOO_LATE } });
  refused.state.updateInstall = { ...READY };
  await refused.install.cancel();
  assert.deepEqual(refused.state.updateInstall, { ...READY, failure: TOO_LATE }, "the staged release is kept");
  assert.deepEqual(refused.logs, [
    ["error", "updater", t("Update not cancelled: {reason}", { reason: macFailureText(TOO_LATE) })],
  ]);
  assert.deepEqual(refused.view().primary, { action: "commit", label: t("Install and Relaunch") });
});

test("a refusal never returns the page to the phase in which Cancel was pressed", async () => {
  const { state, pending, install } = harness();
  state.updateInstall = { ...READY };
  const cancelling = install.cancel();
  void install.commit();
  assert.equal(state.updateInstall.phase, "installing");
  pending.get("cancel_update_install").reject(TOO_LATE);
  await cancelling;
  assert.deepEqual(state.updateInstall, { ...READY, phase: "installing", failure: TOO_LATE });
});

test("a cancellation reply outside the contract is a defect and discards nothing", async () => {
  for (const reply of [{ cancelled: true }, { cancelled: "everything" }, {}, null]) {
    const malformed = harness({ cancel_update_install: reply });
    malformed.state.updateInstall = { ...READY };
    await malformed.install.cancel();
    assert.deepEqual(malformed.state.updateInstall, { ...READY, failure: UNEXPECTED }, JSON.stringify(reply));
    assert.deepEqual(malformed.logs, [[
      "error", "updater",
      t("Update not cancelled: {reason}", {
        reason: macFailureText(UNEXPECTED, "cancel_update_install returned an unexpected reply"),
      }),
    ]], JSON.stringify(reply));
  }
});
