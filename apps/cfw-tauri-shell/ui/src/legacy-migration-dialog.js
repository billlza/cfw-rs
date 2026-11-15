// The dialog that migrates the selected legacy CFM subscription.
import { state } from "./state.js";
import { escapeHtml, errorText, formatBytes } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { normalizeLegacyProfileMigrationOutcome, normalizeLegacyProfileMigrationPreview } from "./migration.js";
import { engineIsOff } from "./engine-identity.js";
import { REASONS } from "./reasons.js";

export function createLegacyMigrationDialog({
  renderPage, renderGlassOverlays, closeGlassOverlays, loadProfilesSnapshot, applyActiveProfile,
}) {
  function render(dialog) {
    const preview = dialog.payload;
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Migrate legacy subscription"))}">
          <h3>${escapeHtml(t("Migrate selected legacy subscription"))}</h3>
          <p class="glass-dialog-copy">${escapeHtml(t("Convert the {size} legacy YAML snapshot saved on this Mac for “{name}”. Migration does not download a newer subscription; {host} is retained only as the HTTPS update source. The cached YAML is never executed, and the converted profile and Keychain credentials are validated before selection.", { size: formatBytes(preview.legacy_bytes), name: preview.name, host: preview.source_host }))}</p>
          ${dialog.error ? `<p class="glass-dialog-copy" role="alert">${escapeHtml(dialog.error)}</p>` : ""}
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss ${dialog.busy ? "disabled" : ""}>${escapeHtml(t("Cancel"))}</button>
            <button type="button" class="glass-btn" data-glass-legacy-migration-confirm data-preview-id="${escapeHtml(preview.preview_id)}" ${dialog.busy ? "disabled" : ""}>${dialog.busy ? t("Migrating…") : t("Import and select")}</button>
          </div>
        </div>
      `);
  }

  function bind() {
    document.querySelectorAll("[data-glass-legacy-migration-confirm]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        const previewId = event.currentTarget.dataset.previewId;
        const dialog = state.glassDialog;
        if (!previewId || dialog?.kind !== "legacy-profile-migration" || dialog.busy) return;
        dialog.busy = true;
        dialog.error = null;
        renderGlassOverlays();
        let committed = false;
        try {
          const outcome = normalizeLegacyProfileMigrationOutcome(
            await invoke("commit_legacy_cfw_profile_migration", {
              previewId,
              confirmed: true,
            }),
          );
          committed = true;
          await loadProfilesSnapshot();
          await applyActiveProfile(t("migrating {name}", { name: outcome.name }));
          appendLog(
            "info",
            "migration",
            t(outcome.reused ? "{name} recovered, credentials verified, and selected" : "{name} imported, credentials verified, and selected", { name: outcome.name }),
          );
          state.legacyProfileMigrationPreview = null;
          closeGlassOverlays();
        } catch (error) {
          const message = errorText(error);
          appendLog(
            "error",
            "migration",
            `${t(committed ? "Migrated profile staging failed" : "Legacy profile migration failed")}: ${message}`,
          );
          state.legacyProfileMigrationPreview = null;
          state.glassDialog = {
            kind: "info",
            payload: committed
              ? {
                title: t("Profile migrated; activation failed"),
                body: t("{message} Reload Profiles and review the selected staged profile; do not resubmit the consumed preview.", { message: message }),
              }
              : {
                title: t("Legacy migration failed"),
                body: t("{message} The one-shot preview is no longer trusted; preview the legacy profile again before retrying.", { message: message }),
              },
          };
          renderGlassOverlays();
        }
        renderPage();
      });
    });
  }

  const actions = {
    "migrate-legacy-profiles": async () => {
      if (state.profilesUnavailableReason) {
        appendLog("error", "profile", t("Profile repository is unavailable: {profilesUnavailableReason}", { profilesUnavailableReason: state.profilesUnavailableReason }));
        renderPage();
        return;
      }
      if (!engineIsOff()) {
        appendLog("warning", "profile", REASONS.engineNotOff);
        renderPage();
        return;
      }
      try {
        const preview = normalizeLegacyProfileMigrationPreview(
          await invoke("preview_legacy_cfw_profile_migration"),
        );
        state.legacyProfileMigrationPreview = preview.status === "ready" ? preview : null;
        if (preview.status === "ready") {
          state.glassDialog = { kind: "legacy-profile-migration", payload: preview, busy: false, error: null };
        } else if (preview.status === "not_subscription") {
          state.glassDialog = {
            kind: "info",
            payload: { title: t("Legacy profile is local"), body: preview.reason },
          };
        } else {
          state.glassDialog = {
            kind: "info",
            payload: { title: t("No selected legacy subscription"), body: t("The legacy settings file does not select a profile that can be migrated.") },
          };
        }
        renderGlassOverlays();
        return;
      } catch (error) {
        const message = errorText(error);
        appendLog("error", "migration", t("Legacy profile preview failed: {message}", { message: message }));
        state.glassDialog = { kind: "info", payload: { title: t("Legacy migration failed"), body: message } };
        renderGlassOverlays();
        return;
      }
    },
  };

  return { dialogs: { kinds: ["legacy-profile-migration"], render, bind }, actions };
}
