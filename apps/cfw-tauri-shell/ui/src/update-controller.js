// Update availability, the About dialog that offers it, and the in-app
// installation of an update.
import { state } from "./state.js";
import { errorText, escapeHtml } from "./text-format.js";
import { invoke, sleep } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { createUpdateInstall, installAfterCheck, updateInstallView } from "./update-install.js";
import { platformPresentation } from "./platform-presentation.js";
import { renderCatLogo } from "./controls.js";

/// Whether `page` shows the update the app offers: General with its badge,
/// and Feedback, the About page.
export function showsUpdateOffer(page) {
  return page === "general" || page === "feedback";
}

export function createUpdateController({ renderPage, renderGlassOverlays, overlayOpen, closeGlassOverlays }) {
  /// Takes what a check found as what the app offers. Answers whether
  /// `payload` says that: anything else changes nothing.
  function applyUpdateInfo(payload) {
    if (!payload || typeof payload !== "object") return false;
    state.updateInfo = {
      available: Boolean(payload.available),
      current: payload.current ?? state.payload?.product?.version,
      version: payload.version ?? null,
      notes: payload.notes ?? null,
      date: payload.date ?? null,
      error: payload.error ?? null,
      install: payload.install ?? null,
    };
    state.updateInstall = installAfterCheck(state.updateInstall, state.updateInfo);
    return true;
  }

  /// What is known of updates once the offer of one was withdrawn: none is
  /// available, for the failure `error` if one says why.
  function withdrawnUpdate(error) {
    return {
      available: false,
      current: state.payload?.product?.version ?? null,
      version: null,
      notes: null,
      date: null,
      error: error ? errorText(error) : null,
    };
  }

  /// Draws the page again where it shows the update the app offers.
  function drawUpdateOffer() {
    if (showsUpdateOffer(state.activePage)) renderPage();
  }

  function invalidateUpdateAuthorization(error) {
    const result = withdrawnUpdate(error);
    applyUpdateInfo(result);
    return result;
  }

  // The update the app offers is what the check that ended last found. The
  // host makes one check, or recheck of an update before its download page
  // opens, at a time and refuses another meanwhile, so a check asked for while
  // one is under way joins it, and each dialog that asked for it shows what it
  // found. An opening of the download page takes the update from the host and
  // withdraws the offer as it ends, unless a check or another opening began
  // since, which says what is offered then. The host announces what each check
  // found as the check ends, that of the app menu among them, which the page
  // learns of only then: an opening may have taken an update announced while
  // it was under way, if the check that found it ended before the host
  // rechecked the update opened, or not, if it ended while the download page
  // opened. The page cannot tell which, so an opening that ends once the host
  // announced an update, and nothing else began since, checks again, and that
  // check says what is offered. The checks, the openings and the announcements
  // are counted in the order they began.
  let begun = 0;
  let asked = 0;
  let sharedCheck = null;

  /// Begins a check or an opening of the download page. Answers what began
  /// since: "nothing", "announcements" where the host announced updates and
  /// nothing else began, or "operations".
  function beginUpdateOperation() {
    begun += 1;
    asked += 1;
    const operation = begun;
    const own = asked;
    return () => {
      if (operation === begun) return "nothing";
      return own === asked ? "announcements" : "operations";
    };
  }

  async function runCheck() {
    // An opening of the download page that ends after this began takes
    // nothing from what it finds.
    beginUpdateOperation();
    try {
      const result = await invoke("check_for_updates");
      applyUpdateInfo(result);
      return result;
    } catch (error) {
      invalidateUpdateAuthorization(error);
      throw error;
    }
  }

  /// The check for updates under way, or a new one. It answers what the host
  /// found, which the app offers then, or fails once the offer was withdrawn
  /// for its failure.
  function checkForUpdates() {
    sharedCheck ??= runCheck().finally(() => { sharedCheck = null; });
    return sharedCheck;
  }

  /// The automatic check at startup, which a check asked for meanwhile joins.
  /// A failure is logged, and no update is offered then.
  async function checkAtStartup() {
    try {
      await checkForUpdates();
    } catch (error) {
      appendLog("error", "updater", t("Automatic update check failed: {error}", { error: errorText(error) }));
    }
  }

  /// Takes the update the host announces as a check ends, which it does for
  /// every check, that of the app menu among them. An opening of the download
  /// page that ends after it checks again.
  function takeAnnouncedUpdate(payload) {
    if (applyUpdateInfo(payload)) begun += 1;
  }

  /// Opens the About dialog with what `options` say, or shows it in the one
  /// that is open, which keeps its place among the open dialogs. Answers the
  /// dialog.
  function openProductAboutDialog(options = {}) {
    const product = state.payload.product;
    const update = options.result
      ? {
          available: Boolean(options.result.available),
          current: options.result.current ?? product.version,
          version: options.result.version ?? null,
          notes: options.result.notes ?? null,
          error: options.result.error ?? null,
          date: options.result.date ?? null,
          install: options.result.install ?? null,
        }
      : state.updateInfo;
    const phase = options.phase
      ?? (options.checking ? "checking" : "idle");
    const payload = { phase, checking: phase === "checking", autoCheck: Boolean(options.autoCheck), update };
    if (state.glassDialog?.kind === "product-about") state.glassDialog.payload = payload;
    else state.glassDialog = { kind: "product-about", payload };
    renderGlassOverlays();
    return state.glassDialog;
  }

  /// Shows what a check of `dialog` came to while `dialog` is open. Once it was
  /// closed, or another dialog took its place, it opens nothing: it would open
  /// again over what the user opened since.
  function showInProductAboutDialog(dialog, options) {
    if (state.glassDialog === dialog) openProductAboutDialog(options);
  }

  /// Checks for updates for the About dialog `dialog`, which shows what the
  /// check came to while it is open, and logs it. The host announces what a
  /// check found, which draws the pages that show it; a failure withdraws the
  /// offer and is announced by nobody, so it draws them here.
  async function checkIn(dialog) {
    try {
      const result = await checkForUpdates();
      appendLog("info", "updater", result?.available
        ? t("Update {version} available", { version: result.version })
        : t("Already up to date ({value1})", { value1: result?.current ?? t("current") }));
      showInProductAboutDialog(dialog, { autoCheck: true, phase: "idle", result });
    } catch (error) {
      appendLog("error", "updater", t("Update check failed: {error}", { error: errorText(error) }));
      showInProductAboutDialog(dialog, { autoCheck: true, phase: "idle", result: withdrawnUpdate(error) });
      drawUpdateOffer();
    }
  }

  /// Shows what the user must be told about an earlier update installation,
  /// unless another overlay is open at that moment: that one is not replaced,
  /// and the log entry is then the only report.
  function showUpdateNotice(notice) {
    if (overlayOpen()) return;
    state.glassDialog = { kind: "info", payload: notice };
    renderGlassOverlays();
  }

  const updateInstall = createUpdateInstall({
    state, invoke, appendLog, errorText, sleep,
    notify: showUpdateNotice,
    onChange: () => { if (state.glassDialog?.kind === "product-about") renderGlassOverlays(); },
  });

  function productAboutStatusText(payload) {
    const phase = payload?.phase ?? (payload?.checking ? "checking" : "idle");
    const update = payload?.update;
    if (phase === "checking") return t("Checking for updates…");
    if (update?.error) return t("Update failed: {error}", { error: update.error });
    if (update?.available && update?.version) {
      return t("Update available: v{version}", { version: update.version });
    }
    if (update && update.available === false) {
      return t("You’re up to date (v{value1})", { value1: update.current ?? state.payload?.product?.version ?? "—" });
    }
    return t("Check GitHub releases for new builds.");
  }

  const actions = {
    "check-for-updates": async () => {
      const dialog = openProductAboutDialog({ autoCheck: true, phase: "checking" });
      try {
        const result = await checkForUpdates();
        showInProductAboutDialog(dialog, { autoCheck: true, phase: "idle", result });
      } catch (error) {
        appendLog("error", "updater", t("Update check failed: {error}", { error: errorText(error) }));
        showInProductAboutDialog(dialog, { autoCheck: true, phase: "idle", result: withdrawnUpdate(error) });
      }
      renderPage();
    },
  };

  function renderProductAboutDialog(dialog) {
    const product = state.payload.product;
    const presentation = platformPresentation(product.operating_system);
    const version = product.version ?? "—";
    const update = dialog.payload?.update;
    const phase = dialog.payload?.phase ?? (dialog.payload?.checking ? "checking" : "idle");
    const installView = updateInstallView(update, state.updateInstall, product.operating_system);
    const status = phase === "checking" ? productAboutStatusText(dialog.payload)
      : installView.status ?? productAboutStatusText(dialog.payload);
    const busy = phase === "checking" || installView.busy;
    const canOpen = Boolean(update?.available && update?.version && !busy && installView.offerDownloadPage);
    const installAction = phase === "checking" ? null : installView.primary;
    const notes = update?.notes ? `<p class="product-about-notes">${escapeHtml(String(update.notes).slice(0, 280))}</p>` : "";
    const primaryLabel = phase === "checking"
      ? t("Checking…")
      : canOpen
        ? t("Open Download v{value1}", { value1: escapeHtml(String(update.version)) })
        : "";
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog product-about" role="dialog" aria-label="${escapeHtml(t("About {product}", { product: product.name }))}">
          <div class="product-about-icon">${renderCatLogo()}</div>
          <div class="product-about-name">${escapeHtml(product.name)}</div>
          <div class="product-about-sub">${escapeHtml(t("Powered by sing-box"))}</div>
          <div class="product-about-meta">
            <div>${escapeHtml(t("Version {version}", { version: String(version) }))}</div>
            <div>${escapeHtml(product.architecture)} · ${presentation.name}${product.minimum_os_version === null ? "" : ` ${escapeHtml(product.minimum_os_version)}+`}</div>
          </div>
          <div class="product-about-status">${escapeHtml(status)}</div>
          ${notes}
          <div class="glass-dialog-actions column">
            ${installAction ? `<button type="button" class="glass-btn" data-glass-update-${installAction.action}>${escapeHtml(installAction.label)}</button>` : ""}
            ${canOpen ? `<button type="button" class="glass-btn${installAction ? " ghost" : ""}" data-glass-open-update>${primaryLabel}</button>` : ""}
            ${phase === "checking" ? `<button type="button" class="glass-btn" disabled>${primaryLabel}</button>` : ""}
            ${installView.cancel ? `<button type="button" class="glass-btn ghost" data-glass-update-cancel>${escapeHtml(t("Cancel"))}</button>` : ""}
            <button type="button" class="glass-btn ghost" data-glass-check-update ${busy ? "disabled" : ""}>${t(phase === "checking" ? "Checking…" : "Check for Update")}</button>
            <button type="button" class="glass-btn ghost" data-glass-dismiss ${busy ? "disabled" : ""}>${escapeHtml(t("Close"))}</button>
          </div>
          <div class="product-about-copy">© ${escapeHtml(product.name)} · ${escapeHtml(product.license)}</div>
        </div>
      `);
  }

  function bindProductAboutDialog() {
    document.querySelectorAll("[data-glass-check-update]").forEach((button) => {
      button.addEventListener("click", () => checkIn(openProductAboutDialog({ autoCheck: true, phase: "checking", result: state.updateInfo })));
    });

    for (const [selector, action] of [
      ["[data-glass-update-install]", updateInstall.prepare],
      ["[data-glass-update-commit]", updateInstall.commit],
      ["[data-glass-update-cancel]", updateInstall.cancel],
    ]) {
      document.querySelectorAll(selector).forEach((button) => {
        button.addEventListener("click", () => action());
      });
    }

    document.querySelectorAll("[data-glass-open-update]").forEach((button) => {
      button.addEventListener("click", async () => {
        const dialog = state.glassDialog;
        const targetVersion = state.updateInfo?.version;
        const since = beginUpdateOperation();
        let opened = false;
        let failure;
        try {
          if (!targetVersion) throw new Error("No validated update is available");
          appendLog("info", "updater", t("Opening the official v{targetVersion} download page…", { targetVersion: targetVersion }));
          await invoke("open_available_update", { expectedVersion: targetVersion });
          opened = true;
          appendLog("info", "updater", t("Official v{targetVersion} download page opened", { targetVersion: targetVersion }));
        } catch (error) {
          failure = error;
          appendLog("error", "updater", t("Could not open update: {error}", { error: errorText(error) }));
        }
        const later = since();
        if (opened) {
          // The host has taken the update it opened. A check begun since offers
          // what it found, which stays.
          if (later === "nothing") invalidateUpdateAuthorization();
          closeGlassOverlays();
        } else if (later === "nothing") {
          showInProductAboutDialog(dialog, { autoCheck: true, phase: "idle", result: invalidateUpdateAuthorization(failure) });
        }
        if (later === "announcements") {
          showInProductAboutDialog(dialog, { autoCheck: true, phase: "checking", result: state.updateInfo });
          await checkIn(dialog);
        }
      });
    });
  }

  return {
    takeAnnouncedUpdate, openProductAboutDialog, updateInstall, checkAtStartup,
    dialogs: { kinds: ["product-about"], render: renderProductAboutDialog, bind: bindProductAboutDialog },
    actions,
  };
}
