// The scripted host and the fixtures of the in-app installation tests. The host
// owns the installation; harness() returns a fresh renderer state, an invoke
// that leaves unscripted commands unanswered, and the views and counters the
// tests read.
import assert from "node:assert/strict";
import nodeTest from "node:test";
import { errorText } from "../../src/text-format.js";
import { t } from "../../src/i18n.js";
import {
  IDLE_UPDATE_INSTALL, createUpdateInstall, installFailureText, updateInstallView,
} from "../../src/update-install.js";

/// The scripted host leaves commands unanswered on purpose. A test that waits
/// for such a command by mistake fails after this long instead of holding the
/// whole run.
const test = (name, body) => nodeTest(name, { timeout: 5_000 }, body);

const macFailureText = (failure, detail = null) => installFailureText(failure, "macos", detail);
const macUpdateInstallView = (update, install) => updateInstallView(update, install, "macos");

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
const NETWORK_LOG = ["error", "updater", t("Update not installed: {reason}", { reason: macFailureText(NETWORK) })];
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
  const state = { payload: { product: { operating_system: "macos" } }, updateInfo: { ...UPDATE }, updateInstall: { ...IDLE_UPDATE_INSTALL } };
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
  const view = () => macUpdateInstallView(state.updateInfo, state.updateInstall);
  const issued = (command) => invoked.filter(([name]) => name === command).length;
  /// Lets the one wait between two questions to the host elapse.
  const elapse = async () => {
    assert.equal(naps.length, 1, "exactly one wait is pending");
    naps.shift().wake();
    await settled();
  };
  return { state, invoked, logs, notices, naps, pending, install, view, issued, elapse, changes: () => changes };
}

const unread = (reason) => [
  "error", "updater",
  t("The state of the update installation could not be read: {reason}", { reason }),
];

export {
  ATTACHED, CANCELLED, CANCELLED_LOG, INSTALL_OFFER, NETWORK, NETWORK_LOG, NEWER, NOTHING_HELD,
  NOTHING_PRESENTED, READY, READY_LOG, TOO_LATE, UNAUTHENTIC, UNEXPECTED, UPDATE, answers, failed,
  failure, harness, held, macFailureText, macUpdateInstallView, resolution, settled, test, unread,
  withdrawn,
};
