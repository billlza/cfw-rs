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

export function createUpdateController({ renderPage, renderGlassOverlays, overlayOpen, closeGlassOverlays }) {
  function applyUpdateInfo(payload) {
    if (!payload || typeof payload !== "object") return;
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
  }

  function invalidateUpdateAuthorization(error) {
    const result = {
      available: false,
      current: state.payload?.product?.version ?? null,
      version: null,
      notes: null,
      date: null,
      error: error ? errorText(error) : null,
    };
    applyUpdateInfo(result);
    return result;
  }

  async function promptAvailableUpdate(result) {
    applyUpdateInfo(result);
    openProductAboutDialog({
      autoCheck: true,
      phase: "idle",
      result,
    });
  }

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
    state.glassDialog = {
      kind: "product-about",
      payload: {
        phase,
        checking: phase === "checking",
        autoCheck: Boolean(options.autoCheck),
        update,
      },
    };
    renderGlassOverlays();
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
      try {
        openProductAboutDialog({ autoCheck: true, phase: "checking" });
        const result = await invoke("check_for_updates");
        await promptAvailableUpdate(result);
      } catch (error) {
        appendLog("error", "updater", t("Update check failed: {error}", { error: errorText(error) }));
        const result = invalidateUpdateAuthorization(error);
        openProductAboutDialog({
          autoCheck: true,
          phase: "idle",
          result,
        });
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
      ? "Checking…"
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
            <div>版本 ${escapeHtml(String(version))}</div>
            <div>${escapeHtml(product.architecture)} · ${presentation.name}${product.minimum_os_version === null ? "" : ` ${escapeHtml(product.minimum_os_version)}+`}</div>
          </div>
          <div class="product-about-status">${escapeHtml(status)}</div>
          ${notes}
          <div class="glass-dialog-actions column">
            ${installAction ? `<button type="button" class="glass-btn" data-glass-update-${installAction.action}>${escapeHtml(installAction.label)}</button>` : ""}
            ${canOpen ? `<button type="button" class="glass-btn${installAction ? " ghost" : ""}" data-glass-open-update>${primaryLabel}</button>` : ""}
            ${phase === "checking" ? `<button type="button" class="glass-btn" disabled>${primaryLabel}</button>` : ""}
            ${installView.cancel ? `<button type="button" class="glass-btn ghost" data-glass-update-cancel>${escapeHtml(t("Cancel"))}</button>` : ""}
            <button type="button" class="glass-btn ghost" data-glass-check-update ${busy ? "disabled" : ""}>${phase === "checking" ? "Checking…" : t("Check for Update")}</button>
            <button type="button" class="glass-btn ghost" data-glass-dismiss ${busy ? "disabled" : ""}>${escapeHtml(t("Close"))}</button>
          </div>
          <div class="product-about-copy">© ${escapeHtml(product.name)} · ${escapeHtml(product.license)}</div>
        </div>
      `);
  }

  function bindProductAboutDialog() {
    document.querySelectorAll("[data-glass-check-update]").forEach((button) => {
      button.addEventListener("click", async () => {
        openProductAboutDialog({ autoCheck: true, phase: "checking", result: state.updateInfo });
        try {
          const result = await invoke("check_for_updates");
          applyUpdateInfo(result);
          appendLog(
            result?.available ? "info" : "info",
            "updater",
            result?.available
              ? t("Update {version} available", { version: result.version })
              : t("Already up to date ({value1})", { value1: result?.current ?? "current" }),
          );
          openProductAboutDialog({ autoCheck: true, phase: "idle", result });
        } catch (error) {
          appendLog("error", "updater", t("Update check failed: {error}", { error: errorText(error) }));
          const result = invalidateUpdateAuthorization(error);
          openProductAboutDialog({
            autoCheck: true,
            phase: "idle",
            result,
          });
        }
      });
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
        const targetVersion = state.updateInfo?.version;
        try {
          if (!targetVersion) throw new Error("No validated update is available");
          appendLog("info", "updater", t("Opening the official v{targetVersion} download page…", { targetVersion: targetVersion }));
          await invoke("open_available_update", { expectedVersion: targetVersion });
          appendLog("info", "updater", t("Official v{targetVersion} download page opened", { targetVersion: targetVersion }));
          invalidateUpdateAuthorization();
          closeGlassOverlays();
        } catch (error) {
          appendLog("error", "updater", t("Could not open update: {error}", { error: errorText(error) }));
          const result = invalidateUpdateAuthorization(error);
          openProductAboutDialog({
            autoCheck: true,
            phase: "idle",
            result,
          });
        }
      });
    });
  }

  return {
    applyUpdateInfo, invalidateUpdateAuthorization, openProductAboutDialog, updateInstall,
    dialogs: { kinds: ["product-about"], render: renderProductAboutDialog, bind: bindProductAboutDialog },
    actions,
  };
}
