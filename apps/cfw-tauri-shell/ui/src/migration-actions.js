// The legacy CFM maintenance actions: opening its session and the one-way cutover.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { loadBootPayload, loadRetirementStatus, markHandoffStatusUnverifiable } from "./migration-session.js";
import {
  clearCutoverReceipt,
  cutoverConfirmArguments,
  cutoverReceiptIsCurrent,
  newCutoverState,
  normalizeCutoverPreparation,
} from "./migration.js";

export function createMigrationActions({ renderPage, loadEngineStatus }) {
  const actions = {
    "open-legacy-maintenance": async () => {
      await loadRetirementStatus();
      state.legacyMaintenanceOpen = true;
      state.activePage = "general";
      await invoke("open_page", { page: "general" });
      renderPage();
    },
    "close-legacy-maintenance": async () => {
      if (!state.migrationHandoff) state.legacyMaintenanceOpen = false;
      renderPage();
    },
    "open-migration-profiles": async () => {
      state.activePage = "profiles";
      await invoke("open_page", { page: "profiles" });
      renderPage();
    },
    "begin-migration-handoff": async () => {
      state.migrationHandoffStatus = { state: "in_progress" };
      renderPage();
      try {
        await invoke("begin_migration_handoff");
        appendLog("info", "migration", t("Launching the signed migration session…"));
        state.cutover.message = t("The verified migration window is ready. This dashboard will now close.");
      } catch (error) {
        try {
          await loadBootPayload();
        } catch (refreshError) {
          markHandoffStatusUnverifiable(refreshError);
        }
        appendLog("error", "migration", t("Could not start the migration session: {error}", { error: errorText(error) }));
      }
      renderPage();
    },
    "prepare-cutover": async () => {
      const requestedTarget = state.cutover.target;
      state.cutover = clearCutoverReceipt(state.cutover, {
        targetValue: requestedTarget,
        message: null,
      });
      state.cutover.busy = true;
      renderPage();
      try {
        const response = await invoke("prepare_legacy_cutover", { target: requestedTarget });
        const preparation = normalizeCutoverPreparation(response, requestedTarget);
        if (preparation.status === "ready") {
          state.cutover.receiptId = preparation.receiptId;
          state.cutover.receiptTarget = preparation.target;
          state.cutover.receiptIssuedAt = preparation.issuedAt;
          state.cutover.receiptExpiresAt = preparation.expiresAt;
          state.cutover.awaitingApproval = false;
          state.cutover.message = t("Replacement staged and validated. Confirm the one-way cutover to proceed.");
        } else if (preparation.status === "awaiting_approval") {
          state.cutover.awaitingApproval = true;
          state.cutover.message = t("System Extension approval is pending.");
        }
      } catch (error) {
        state.cutover = clearCutoverReceipt(state.cutover, {
          targetValue: requestedTarget,
          message: errorText(error),
        });
        appendLog("error", "migration", t("Prepare cutover failed: {error}", { error: errorText(error) }));
      } finally {
        state.cutover.busy = false;
      }
      renderPage();
    },
    "confirm-cutover": async () => {
      let confirmArgs;
      try {
        confirmArgs = cutoverConfirmArguments(state.cutover);
      } catch (error) {
        if (cutoverReceiptIsCurrent(state.cutover)) {
          state.cutover.message = errorText(error);
        } else {
          state.cutover = clearCutoverReceipt(state.cutover, {
            message: errorText(error),
          });
        }
      }
      if (confirmArgs) {
        state.cutover.busy = true;
        state.cutover.message = null;
        renderPage();
        try {
          await invoke("disable_service_mode", confirmArgs);
          state.cutover = newCutoverState(state.cutover.target, t("Cutover complete. Replacement networking is active."));
          appendLog("info", "migration", t("Legacy network retired; replacement is active."));
          await loadEngineStatus();
          await loadRetirementStatus();
        } catch (error) {
          state.cutover = clearCutoverReceipt(state.cutover, { message: errorText(error) });
          appendLog("error", "migration", t("Cutover failed: {error}", { error: errorText(error) }));
          await loadRetirementStatus();
        } finally {
          state.cutover.busy = false;
        }
      }
      renderPage();
    },
    "recover-cutover": async () => {
      state.cutover = clearCutoverReceipt(state.cutover, { message: null });
      state.cutover.busy = true;
      renderPage();
      try {
        await invoke("recover_legacy_cutover");
        state.cutover.message = t("Recovery complete.");
        appendLog("info", "migration", t("Interrupted cutover recovered."));
        await loadEngineStatus();
        await loadRetirementStatus();
      } catch (error) {
        state.cutover.message = errorText(error);
        appendLog("error", "migration", t("Recovery failed: {error}", { error: errorText(error) }));
        await loadRetirementStatus();
      } finally {
        state.cutover.busy = false;
      }
      renderPage();
    },
  };

  function bindPage() {
    const cutoverConfirm = document.querySelector("[data-cutover-confirm]");
    if (cutoverConfirm) {
      cutoverConfirm.addEventListener("change", (event) => {
        state.cutover.confirmedReceiptId = event.currentTarget.checked === true
          ? state.cutover.receiptId
          : null;
      });
    }

    const cutoverDnsReview = document.querySelector("[data-cutover-dns-review]");
    if (cutoverDnsReview) {
      cutoverDnsReview.addEventListener("change", (event) => {
        state.cutover.dnsReviewedReceiptId = event.currentTarget.checked === true
          ? state.cutover.receiptId
          : null;
      });
    }

    const cutoverTarget = document.querySelector("[data-cutover-target]");
    if (cutoverTarget) {
      cutoverTarget.addEventListener("change", (event) => {
        const target = event.currentTarget.value;
        if (target !== "system_proxy" && target !== "tunnel") return;
        state.cutover = clearCutoverReceipt(state.cutover, { targetValue: target, message: null });
        renderPage();
      });
    }
  }

  return { actions, bindPage };
}
