import { t } from "./i18n.js";

// One sentence per failure category the host reports. The stable code is
// appended for diagnostics and is never translated.
const FAILURE_TEXT = Object.freeze({
  state: () => t("The update changed or is no longer available. Check for updates again."),
  busy: () => t("Another update operation is in progress. Try again in a moment."),
  environment: () => t("This copy cannot update itself. Download the disk image and replace the app in Applications."),
  network: () => t("The download did not complete. Check the connection and try again."),
  storage: () => t("The update could not be stored on this Mac. Free some disk space and try again."),
  authenticity: () => t("The downloaded update is not the signed release and was discarded. Do not install it from another source."),
  package: () => t("This release cannot be installed on this Mac."),
  engine: () => t("The core could not be stopped. Stop the core and try again."),
  internal: () => t("The update could not be installed because of an internal error."),
});

// What a check reports for a release that failed authentication earlier in
// this run of the application.
const UNAUTHENTIC_RELEASE = "release_failed_authentication";

// The phase this page shows for an installation the host still holds, and
// the kind of held installation each shown phase stands for.
const ATTACHED_PHASE = Object.freeze({ preparing: "downloading", staged: "ready", committing: "installing" });
const HELD_AS = Object.freeze({
  downloading: "preparing", verifying: "preparing", ready: "staged", installing: "committing",
});

// How an attempt ended when this page was given no failure for it.
const ENDED_TEXT = Object.freeze({
  cancelled: () => t("Update download cancelled"),
  unreported: () => t("The update installation is no longer in progress. Check for updates again."),
});

// A re-attached installation is asked about this often, one request at a time.
const FOLLOW_INTERVAL_MS = 1000;

/// `failure` and `ended` say how the last attempt ended. While idle, either of
/// them means that attempt consumed the presented release.
export const IDLE_UPDATE_INSTALL = Object.freeze({
  phase: "idle", version: null, downloaded: 0, total: null, failure: null, ended: null,
});

function isHostFailure(error) {
  return Boolean(error) && typeof error === "object"
    && typeof error.code === "string" && /^[a-z0-9_]{1,64}$/.test(error.code)
    && typeof error.category === "string" && Object.hasOwn(FAILURE_TEXT, error.category);
}

/// The host rejects installation commands with `{ code, category }`. Anything
/// else is a defect in this dashboard or the bridge, not a category the user
/// can act on.
export function normalizeInstallFailure(error) {
  return isHostFailure(error)
    ? { code: error.code, category: error.category }
    : { code: "unexpected_error", category: "internal" };
}

/// `detail` is the text of a rejection the host does not define. It is kept
/// beside the code so the log still says what was received.
export function installFailureText(failure, detail = null) {
  const code = detail === null ? failure.code : `${failure.code}: ${detail}`;
  return `${FAILURE_TEXT[failure.category]()} (${code})`;
}

function byteCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function downloadStatus(install) {
  const { downloaded, total } = install;
  if (total > 0 && byteCount(total) !== null && byteCount(downloaded) !== null) {
    const percent = Math.min(100, Math.floor((downloaded * 100) / total));
    return t("Downloading update… {percent}%", { percent });
  }
  return t("Downloading update…");
}

/// What the About dialog shows for the presented `update` and the
/// installation this page follows.
///
/// A running or staged installation is shown whatever release is presented:
/// the host holds it until it is installed or cancelled. While idle the
/// dialog offers only what the host accepts. Every attempt consumes the
/// presented release, so after one ended neither the installation nor the
/// download page is offered until a fresh check, and a release that failed
/// authentication is never answered by pointing at another copy of it.
///
/// `status` replaces the dialog's own status line when it is not null.
export function updateInstallView(update, install) {
  const { phase, version } = install;
  const failureStatus = install.failure ? installFailureText(install.failure) : null;
  if (phase === "downloading" || phase === "verifying") {
    return {
      status: phase === "downloading" ? downloadStatus(install) : t("Verifying update…"),
      primary: null, cancel: true, busy: true, offerDownloadPage: false,
    };
  }
  if (phase === "installing") {
    return {
      status: t("Installing update… Clash for Mac will reopen automatically."),
      primary: null, cancel: false, busy: true, offerDownloadPage: false,
    };
  }
  if (phase === "ready") {
    return {
      status: failureStatus ?? t("v{version} is ready to install. Clash for Mac will stop the core, quit, and reopen.", { version }),
      primary: { action: "commit", label: t("Install and Relaunch") },
      cancel: true, busy: false, offerDownloadPage: false,
    };
  }
  const available = Boolean(update?.available && update?.version);
  const ended = failureStatus ?? (install.ended ? ENDED_TEXT[install.ended]() : null);
  if (ended !== null || (available && update.install?.code === UNAUTHENTIC_RELEASE)) {
    return {
      status: ended ?? installFailureText({ code: UNAUTHENTIC_RELEASE, category: "authenticity" }),
      primary: null, cancel: false, busy: false, offerDownloadPage: false,
    };
  }
  return {
    status: null,
    primary: available && update.install?.supported === true
      ? { action: "install", label: t("Install Update v{version}", { version: update.version }) }
      : null,
    cancel: false, busy: false, offerDownloadPage: true,
  };
}

/// The installation this page follows once a check presented `update`.
///
/// The host holds a new authorization for what a check presents, so the check
/// supersedes how an earlier attempt ended. Two things outlive it: a running
/// or staged installation, which belongs to the host, and an authenticity
/// failure of the very release that is presented again.
export function installAfterCheck(install, update) {
  if (install.phase !== "idle") return install;
  const presentedAgain = Boolean(update?.available) && update.version === install.version;
  if (install.failure?.category === "authenticity" && presentedAgain) return install;
  return { ...IDLE_UPDATE_INSTALL };
}

/// Accepts the reply of `cancel_update_install` only in its exact shape.
function readCancellation(reply) {
  const cancelled = reply?.cancelled;
  if (cancelled !== "nothing" && cancelled !== "preparation" && cancelled !== "staged") {
    throw new Error("cancel_update_install returned an unexpected reply");
  }
  return cancelled;
}

/// Accepts the reply of `resolve_update_install` only in its exact shape.
function readResolution(reply) {
  const outcome = reply?.outcome;
  const pending = reply?.pending;
  const outcomeDefined = outcome?.state === "none"
    || (outcome?.state === "installed" && typeof outcome.version === "string")
    || (outcome?.state === "failed" && typeof outcome.version === "string" && typeof outcome.code === "string");
  const pendingDefined = pending === null
    || (typeof pending?.phase === "string" && Object.hasOwn(ATTACHED_PHASE, pending.phase)
      && typeof pending.version === "string");
  if (!outcomeDefined || !pendingDefined) {
    throw new Error("resolve_update_install returned an unexpected reply");
  }
  return { outcome, pending };
}

/// Owns the renderer's view of one installation. The host owns the
/// installation itself: every transition here follows a host reply or event,
/// and every action is one the view currently offers.
export function createUpdateInstall({ state, invoke, appendLog, errorText, sleep, notify, onChange }) {
  // The preparation whose reply this page still expects. Once the host has
  // confirmed that nothing of it is left, its reply finds another value here
  // and no longer moves the view.
  let awaited = null;
  // The installation this page was re-attached to and asks the host about:
  // the replies that end it went to the page that started it.
  let followed = null;

  const offered = () => updateInstallView(state.updateInfo, state.updateInstall);
  const shows = (held) => HELD_AS[state.updateInstall.phase] === held.phase
    && state.updateInstall.version === held.version;

  function set(next) {
    state.updateInstall = { ...state.updateInstall, ...next };
    // An installation the view has left is forgotten, so that a later one of
    // the same release is never taken for it.
    if (followed !== null && !shows(followed)) followed = null;
    onChange();
  }

  /// The failure a rejection carries and the sentence the log records for it.
  function describe(error) {
    const failure = normalizeInstallFailure(error);
    return { failure, text: installFailureText(failure, isHostFailure(error) ? null : errorText(error)) };
  }

  function endCancelled() {
    awaited = null;
    appendLog("info", "updater", ENDED_TEXT.cancelled());
    set({ ...IDLE_UPDATE_INSTALL, version: state.updateInstall.version, ended: "cancelled" });
  }

  /// A preparation that completes after this page stopped waiting for it
  /// leaves a staged release that no view shows. The host is told to discard
  /// it; otherwise it would refuse every later preparation.
  async function discardUnshown() {
    try {
      readCancellation(await invoke("cancel_update_install"));
    } catch (error) {
      appendLog("error", "updater", t("Update not cancelled: {reason}", { reason: describe(error).text }));
    }
  }

  async function prepare() {
    if (offered().primary?.action !== "install") return;
    const { version } = state.updateInfo;
    const attempt = Symbol("preparation");
    awaited = attempt;
    set({ ...IDLE_UPDATE_INSTALL, phase: "downloading", version });
    try {
      await invoke("prepare_update_install", { expectedVersion: version });
    } catch (error) {
      const { failure, text } = describe(error);
      const current = awaited === attempt;
      if (failure.code === "download_cancelled") {
        // A cancellation the host confirmed first has already been reported.
        if (current) endCancelled();
        return;
      }
      appendLog("error", "updater", t("Update not installed: {reason}", { reason: text }));
      if (current) {
        awaited = null;
        set({ ...IDLE_UPDATE_INSTALL, version, failure });
      }
      return;
    }
    if (awaited !== attempt) {
      await discardUnshown();
      return;
    }
    awaited = null;
    set({ phase: "ready", failure: null });
    appendLog("info", "updater", t("Update v{version} is verified and ready to install", { version }));
  }

  async function cancel() {
    if (!offered().cancel) return;
    let cancelled;
    try {
      cancelled = readCancellation(await invoke("cancel_update_install"));
    } catch (error) {
      // A refusal changes nothing on the host, and a reply outside the
      // contract says nothing about it: the phase stays what the other
      // replies made it.
      const { failure, text } = describe(error);
      appendLog("error", "updater", t("Update not cancelled: {reason}", { reason: text }));
      set({ failure });
      return;
    }
    // A preparation this page started ends through its own rejection. One it
    // was re-attached to has no reply left that could end it.
    if (cancelled === "preparation" && awaited !== null) return;
    // Nothing is left that could be installed. A page that is idle already
    // has reported what ended the installation, with its own reason.
    if (state.updateInstall.phase !== "idle") endCancelled();
  }

  async function commit() {
    if (offered().primary?.action !== "commit") return;
    const { version } = state.updateInstall;
    set({ phase: "installing", failure: null });
    try {
      await invoke("commit_update_install", { expectedVersion: version });
    } catch (error) {
      const { failure, text } = describe(error);
      appendLog("error", "updater", t("Update not installed: {reason}", { reason: text }));
      // A cancellation the host confirmed meanwhile has already ended this.
      if (state.updateInstall.phase !== "installing") return;
      // A failed hand-off keeps the verified release staged on the host,
      // unless the host says it holds none.
      set(failure.code === "no_staged_update"
        ? { ...IDLE_UPDATE_INSTALL, version, failure }
        : { phase: "ready", failure });
      return;
    }
    appendLog("info", "updater", t("Installing update… Clash for Mac will reopen automatically."));
  }

  function onProgress(payload) {
    const install = state.updateInstall;
    if (!payload || typeof payload !== "object" || payload.version !== install.version) return;
    if (install.phase !== "downloading" && install.phase !== "verifying") return;
    if (payload.phase === "downloading") {
      set({
        phase: "downloading",
        downloaded: byteCount(payload.downloaded) ?? 0,
        total: byteCount(payload.total),
      });
    } else if (payload.phase === "verifying") {
      set({ phase: "verifying" });
    }
  }

  /// Logs what the previous installation attempt left behind and has a
  /// failure shown as well.
  function report(outcome) {
    if (outcome.state === "installed") {
      appendLog("info", "updater", t("Updated to v{version}", { version: outcome.version }));
    } else if (outcome.state === "failed") {
      const title = t("Update v{version} was not installed", { version: outcome.version });
      const body = t("The previous version is still installed. Reason code: {code}", { code: outcome.code });
      appendLog("error", "updater", `${title}: ${body}`);
      notify({ title, body });
    }
  }

  /// Shows an installation the host holds without this page having started
  /// it, for example after the dashboard was reloaded. The replies that end a
  /// running one went to the page that started it, so this page follows it by
  /// asking; a staged release waits for the user and needs no asking.
  function attach(pending) {
    set({ ...IDLE_UPDATE_INSTALL, phase: ATTACHED_PHASE[pending.phase], version: pending.version });
    if (pending.phase === "staged") return;
    const attachment = { phase: pending.phase, version: pending.version };
    followed = attachment;
    void follow(attachment);
  }

  /// Asks the host what it still holds until the view leaves the installation
  /// it was attached to: because the host staged the release, because the
  /// host holds nothing any more, or because the user cancelled. Whatever else
  /// changed the view ends the asking as well.
  async function follow(attachment) {
    const following = () => followed === attachment && shows(attachment);
    let unanswered = null;
    while (following()) {
      await sleep(FOLLOW_INTERVAL_MS);
      if (!following()) return;
      let resolution;
      try {
        resolution = readResolution(await invoke("resolve_update_install"));
      } catch (error) {
        // The same refusal is logged once, however long the host repeats it.
        const text = t("The state of the update installation could not be read: {reason}", { reason: describe(error).text });
        if (text !== unanswered) appendLog("error", "updater", text);
        unanswered = text;
        continue;
      }
      unanswered = null;
      report(resolution.outcome);
      if (!following()) return;
      const { pending } = resolution;
      if (pending === null) {
        appendLog("warning", "updater", ENDED_TEXT.unreported());
        set({ ...IDLE_UPDATE_INSTALL, version: attachment.version, ended: "unreported" });
        return;
      }
      if (pending.phase === attachment.phase && pending.version === attachment.version) continue;
      attach(pending);
      if (pending.phase === "staged") {
        appendLog("info", "updater", t("Update v{version} is verified and ready to install", { version: pending.version }));
      }
      return;
    }
  }

  /// Asks the host what the previous installation attempt left behind and
  /// which installation it still holds. What that attempt left behind is
  /// logged, and so is a review that failed; a failure of either is shown as
  /// well.
  async function resolveOutcome() {
    let resolution;
    try {
      resolution = readResolution(await invoke("resolve_update_install"));
    } catch (error) {
      const body = t("The previous update attempt could not be reviewed: {reason}", { reason: describe(error).text });
      appendLog("error", "updater", body);
      notify({ title: t("Updates"), body });
      return;
    }
    report(resolution.outcome);
    // An installation this page started is followed through its own replies.
    if (resolution.pending !== null && state.updateInstall.phase === "idle") attach(resolution.pending);
  }

  return { prepare, cancel, commit, onProgress, resolveOutcome };
}
