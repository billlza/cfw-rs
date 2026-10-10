// Exercises the renderer's view of an in-app installation against a scripted
// host. The host owns the installation; these tests pin what the dashboard
// shows and which command each action issues.
import assert from "node:assert/strict";
import nodeTest from "node:test";
import { errorText } from "../src/format.js";
import { t } from "../src/i18n.js";
import {
  IDLE_UPDATE_INSTALL, createUpdateInstall, installAfterCheck, installFailureText,
  normalizeInstallFailure, updateInstallView,
} from "../src/update-install.js";

/// The scripted host leaves commands unanswered on purpose. A test that waits
/// for such a command by mistake fails after this long instead of holding the
/// whole run.
const test = (name, body) => nodeTest(name, { timeout: 5_000 }, body);

const UPDATE = Object.freeze({ available: true, version: "0.5.0", install: { supported: true } });
const NEWER = Object.freeze({ ...UPDATE, version: "0.5.1" });
const UNAUTHENTIC = Object.freeze({
  ...UPDATE, install: { supported: false, code: "release_failed_authentication" },
});
const NOTHING_PRESENTED = Object.freeze({ available: false, version: null });

const READY = Object.freeze({ ...IDLE_UPDATE_INSTALL, phase: "ready", version: "0.5.0" });
const CANCELLED = Object.freeze({ ...IDLE_UPDATE_INSTALL, version: "0.5.0", ended: "cancelled" });
const INSTALL_OFFER = Object.freeze({
  action: "install", label: t("Install Update v{version}", { version: "0.5.0" }),
});

const failure = (code, category) => ({ code, category });
const UNEXPECTED = failure("unexpected_error", "internal");
const NETWORK = failure("network", "network");
const TOO_LATE = failure("cancellation_too_late", "state");
const READY_LOG = ["info", "updater", t("Update v{version} is verified and ready to install", { version: "0.5.0" })];
const CANCELLED_LOG = ["info", "updater", t("Update download cancelled")];
const NETWORK_LOG = ["error", "updater", t("Update not installed: {reason}", { reason: installFailureText(NETWORK) })];
const failed = (reason) => ({ ...IDLE_UPDATE_INSTALL, version: "0.5.0", failure: reason });
const withdrawn = (status) => ({
  status, primary: null, cancel: false, busy: false, offerDownloadPage: false,
});
const resolution = (outcome, pending = null) => ({ outcome, pending });
const held = (phase, version = "0.4.9") => resolution({ state: "none" }, { phase, version });
const NOTHING_HELD = resolution({ state: "none" });
const ATTACHED = Object.freeze({ ...IDLE_UPDATE_INSTALL, phase: "downloading", version: "0.4.9" });

const UNANSWERED = Symbol("unanswered");
/// Answers one call after the other; a call beyond the script stays unanswered
/// until the test settles it through `pending`.
const answers = (...replies) => () => (replies.length > 0 ? replies.shift() : UNANSWERED);
/// Lets everything that is ready to run finish.
const settled = () => new Promise((resolve) => setImmediate(resolve));

function harness(replies = {}) {
  const state = { updateInfo: { ...UPDATE }, updateInstall: { ...IDLE_UPDATE_INSTALL } };
  const invoked = [];
  const logs = [];
  const notices = [];
  const naps = [];
  let changes = 0;
  const pending = new Map();
  const invoke = (command, args) => {
    invoked.push([command, args]);
    const scripted = Object.hasOwn(replies, command) ? replies[command] : UNANSWERED;
    const reply = typeof scripted === "function" ? scripted() : scripted;
    if (reply === UNANSWERED) {
      return new Promise((resolve, reject) => pending.set(command, { resolve, reject }));
    }
    return reply instanceof Error || reply?.reject
      ? Promise.reject(reply.reject ?? reply)
      : Promise.resolve(reply);
  };
  const install = createUpdateInstall({
    state, invoke, errorText,
    appendLog: (level, source, message) => logs.push([level, source, message]),
    sleep: (milliseconds) => new Promise((wake) => naps.push({ milliseconds, wake })),
    notify: (notice) => notices.push(notice),
    onChange: () => { changes += 1; },
  });
  const view = () => updateInstallView(state.updateInfo, state.updateInstall);
  const issued = (command) => invoked.filter(([name]) => name === command).length;
  /// Lets the one wait between two questions to the host elapse.
  const elapse = async () => {
    assert.equal(naps.length, 1, "exactly one wait is pending");
    naps.shift().wake();
    await settled();
  };
  return { state, invoked, logs, notices, naps, pending, install, view, issued, elapse, changes: () => changes };
}

test("an installable release offers the installation and keeps the download page", () => {
  const view = updateInstallView(UPDATE, IDLE_UPDATE_INSTALL);
  assert.deepEqual(view, {
    status: null, primary: INSTALL_OFFER, cancel: false, busy: false, offerDownloadPage: true,
  });
});

test("a copy that cannot replace itself is offered only the download page", () => {
  for (const install of [{ supported: false, code: "not_in_applications" }, null, undefined]) {
    const view = updateInstallView({ ...UPDATE, install }, IDLE_UPDATE_INSTALL);
    assert.equal(view.primary, null);
    assert.equal(view.offerDownloadPage, true);
    assert.equal(view.busy, false);
  }
  assert.equal(updateInstallView({ available: false }, IDLE_UPDATE_INSTALL).primary, null);
  assert.equal(updateInstallView(null, IDLE_UPDATE_INSTALL).primary, null);
});

test("download and verification show progress, allow cancellation and block other actions", () => {
  const downloading = { ...IDLE_UPDATE_INSTALL, phase: "downloading", version: "0.5.0", downloaded: 30, total: 120 };
  assert.deepEqual(updateInstallView(UPDATE, downloading), {
    status: t("Downloading update… {percent}%", { percent: 25 }),
    primary: null, cancel: true, busy: true, offerDownloadPage: false,
  });
  assert.equal(
    updateInstallView(UPDATE, { ...downloading, total: null }).status,
    t("Downloading update…"),
  );
  assert.equal(
    updateInstallView(UPDATE, { ...downloading, downloaded: 500 }).status,
    t("Downloading update… {percent}%", { percent: 100 }),
    "a reply that overshoots its announced size never shows more than 100%",
  );
  assert.deepEqual(updateInstallView(UPDATE, { ...downloading, phase: "verifying" }), {
    status: t("Verifying update…"),
    primary: null, cancel: true, busy: true, offerDownloadPage: false,
  });
});

test("a staged release asks for the disconnecting step explicitly", () => {
  assert.deepEqual(updateInstallView(UPDATE, READY), {
    status: t("v{version} is ready to install. Clash for Mac will stop the core, quit, and reopen.", { version: "0.5.0" }),
    primary: { action: "commit", label: t("Install and Relaunch") },
    cancel: true, busy: false, offerDownloadPage: false,
  });
  const installing = updateInstallView(UPDATE, { ...READY, phase: "installing" });
  assert.equal(installing.primary, null);
  assert.equal(installing.cancel, false);
  assert.equal(installing.busy, true);
});

test("a running or staged installation is shown whatever release is presented", () => {
  for (const phase of ["downloading", "verifying", "ready", "installing"]) {
    const install = { ...IDLE_UPDATE_INSTALL, phase, version: "0.5.0", downloaded: 30, total: 120 };
    const shown = updateInstallView(UPDATE, install);
    assert.notDeepEqual(shown, updateInstallView(UPDATE, IDLE_UPDATE_INSTALL), phase);
    for (const presented of [NEWER, UNAUTHENTIC, NOTHING_PRESENTED, { available: false, error: "offline" }, null]) {
      assert.deepEqual(updateInstallView(presented, install), shown, `${phase}: ${JSON.stringify(presented)}`);
    }
  }
  const staged = updateInstallView(NEWER, READY);
  assert.equal(
    staged.status,
    t("v{version} is ready to install. Clash for Mac will stop the core, quit, and reopen.", { version: "0.5.0" }),
    "the status names the staged release, not the presented one",
  );
  assert.deepEqual(staged.primary, { action: "commit", label: t("Install and Relaunch") });
  assert.equal(staged.cancel, true);
});

test("an attempt that ended without a staged release withdraws both offers", () => {
  const network = failed(NETWORK);
  for (const presented of [UPDATE, NEWER, NOTHING_PRESENTED, null]) {
    assert.deepEqual(
      updateInstallView(presented, network),
      withdrawn(installFailureText(network.failure)),
      `failed: ${JSON.stringify(presented)}`,
    );
    assert.deepEqual(
      updateInstallView(presented, CANCELLED),
      withdrawn(t("Update download cancelled")),
      `cancelled: ${JSON.stringify(presented)}`,
    );
  }
  assert.ok(updateInstallView(UPDATE, network).status.endsWith("(network)"));
});

test("a fresh check supersedes how an earlier attempt ended", () => {
  for (const ended of [failed(NETWORK), { ...CANCELLED }]) {
    for (const presented of [UPDATE, NEWER, NOTHING_PRESENTED]) {
      assert.deepEqual(installAfterCheck(ended, presented), IDLE_UPDATE_INSTALL);
    }
    assert.deepEqual(updateInstallView(UPDATE, installAfterCheck(ended, UPDATE)), {
      status: null, primary: INSTALL_OFFER, cancel: false, busy: false, offerDownloadPage: true,
    });
  }
});

test("a check never disturbs a running or staged installation", () => {
  for (const phase of ["downloading", "verifying", "ready", "installing"]) {
    const install = {
      ...IDLE_UPDATE_INSTALL, phase, version: "0.5.0", downloaded: 30, total: 120,
      failure: failure("engine_stop_failed", "engine"),
    };
    for (const presented of [UPDATE, NEWER, UNAUTHENTIC, NOTHING_PRESENTED]) {
      assert.equal(installAfterCheck(install, presented), install, `${phase}: ${JSON.stringify(presented)}`);
    }
  }
});

test("an authenticity failure outlives every check that presents the same release", () => {
  const forged = failed(failure("signature_mismatch", "authenticity"));
  const view = updateInstallView(UPDATE, forged);
  assert.deepEqual(view, withdrawn(installFailureText(forged.failure)));
  assert.ok(view.status.endsWith("(signature_mismatch)"));

  for (const presentedAgain of [UPDATE, UNAUTHENTIC, { ...UPDATE, install: null }]) {
    assert.equal(installAfterCheck(forged, presentedAgain), forged, JSON.stringify(presentedAgain));
  }
  for (const other of [NEWER, NOTHING_PRESENTED, { available: false, version: "0.5.0" }]) {
    assert.deepEqual(installAfterCheck(forged, other), IDLE_UPDATE_INSTALL, JSON.stringify(other));
  }
});

test("the host's verdict on a release that failed authentication withdraws both offers", () => {
  const verdict = installFailureText(failure("release_failed_authentication", "authenticity"));
  assert.deepEqual(updateInstallView(UNAUTHENTIC, IDLE_UPDATE_INSTALL), withdrawn(verdict));
  assert.equal(
    verdict,
    `${t("The downloaded update is not the signed release and was discarded. Do not install it from another source.")} (release_failed_authentication)`,
  );
  assert.equal(
    updateInstallView({ ...UNAUTHENTIC, install: { supported: true, code: "release_failed_authentication" } }, IDLE_UPDATE_INSTALL).primary,
    null,
    "the verdict wins over a contradictory support flag",
  );
  assert.equal(
    updateInstallView({ ...UNAUTHENTIC, available: false }, IDLE_UPDATE_INSTALL).status,
    null,
    "a verdict on a release that is not presented says nothing",
  );
  assert.equal(
    updateInstallView({ ...UPDATE, install: { supported: false, code: "not_in_applications" } }, IDLE_UPDATE_INSTALL).offerDownloadPage,
    true,
    "any other reason leaves the download page",
  );
});

test("host failures are accepted only in their exact shape", () => {
  assert.deepEqual(
    normalizeInstallFailure({ code: "archive_layout_invalid", category: "package" }),
    failure("archive_layout_invalid", "package"),
  );
  assert.deepEqual(
    normalizeInstallFailure({ code: "network", category: "network", detail: "ignored", attempts: 3 }),
    failure("network", "network"),
    "only the two fields the host defines are kept",
  );
  const categories = ["state", "busy", "environment", "network", "storage", "authenticity", "package", "engine", "internal"];
  const sentences = categories.map((category) => {
    assert.deepEqual(normalizeInstallFailure({ code: "some_code", category }), failure("some_code", category));
    return installFailureText(failure("some_code", category));
  });
  assert.equal(new Set(sentences).size, categories.length, "every category has its own sentence");
  for (const sentence of sentences) assert.ok(sentence.endsWith(" (some_code)"), sentence);
  assert.equal(
    installFailureText(failure("install_already_active", "busy")),
    `${t("Another update operation is in progress. Try again in a moment.")} (install_already_active)`,
  );

  for (const invalid of [
    null, undefined, "network", new Error("boom"),
    { code: "network", category: "unknown" },
    { code: "network", category: ["network"] },
    { code: "<script>", category: "network" },
    { code: "", category: "network" },
    { code: "x".repeat(65), category: "network" },
    { code: "network", category: "__proto__" },
    { category: "network" },
  ]) {
    assert.deepEqual(normalizeInstallFailure(invalid), UNEXPECTED, JSON.stringify(invalid));
  }
  assert.ok(installFailureText(UNEXPECTED).endsWith("(unexpected_error)"));
  assert.ok(installFailureText(UNEXPECTED, "bridge closed").endsWith("(unexpected_error: bridge closed)"));
});

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
    ["error", "updater", t("Update not installed: {reason}", { reason: installFailureText(forged) })],
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
      ["error", "updater", t("Update not installed: {reason}", { reason: installFailureText(UNEXPECTED, text) })],
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
    [{ reject: TOO_LATE }, installFailureText(TOO_LATE)],
    [{ cancelled: true }, installFailureText(UNEXPECTED, "cancel_update_install returned an unexpected reply")],
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
    ["error", "updater", t("Update not cancelled: {reason}", { reason: installFailureText(TOO_LATE) })],
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
        reason: installFailureText(UNEXPECTED, "cancel_update_install returned an unexpected reply"),
      }),
    ]], JSON.stringify(reply));
  }
});

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
  assert.equal(busy.view().status, installFailureText(stopFailed));
  assert.deepEqual(busy.logs, [
    ["error", "updater", t("Update not installed: {reason}", { reason: installFailureText(stopFailed) })],
  ]);

  const missing = failure("no_staged_update", "state");
  const gone = harness({ commit_update_install: { reject: missing } });
  gone.state.updateInstall = { ...READY };
  await gone.install.commit();
  assert.deepEqual(gone.state.updateInstall, failed(missing));
  assert.deepEqual(
    gone.view(), withdrawn(installFailureText(missing)),
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
    ["error", "updater", t("Update not installed: {reason}", { reason: installFailureText(active) })],
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
    [journal, installFailureText(journal)],
    ["journal task ended", installFailureText(UNEXPECTED, "journal task ended")],
    [new Error("bridge closed"), installFailureText(UNEXPECTED, "bridge closed")],
  ]) {
    const unavailable = harness({ resolve_update_install: { reject: rejection } });
    const body = t("The previous update attempt could not be reviewed: {reason}", { reason });
    await unavailable.install.resolveOutcome();
    assert.deepEqual(unavailable.notices, [{ title: t("Updates"), body }]);
    assert.deepEqual(unavailable.logs, [["error", "updater", body]]);
    assert.deepEqual(unavailable.state.updateInstall, IDLE_UPDATE_INSTALL);
    assert.deepEqual(unavailable.naps, []);
  }
  assert.ok(installFailureText(journal).endsWith("(journal_failed)"));
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
      reason: installFailureText(UNEXPECTED, "resolve_update_install returned an unexpected reply"),
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
const unread = (reason) => [
  "error", "updater",
  t("The state of the update installation could not be read: {reason}", { reason }),
];
const REFUSED_LOG = unread(installFailureText(JOURNAL));
const MALFORMED_LOG = unread(installFailureText(UNEXPECTED, "resolve_update_install returned an unexpected reply"));

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
