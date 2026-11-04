// The boot payload of this window, its migration handoff state, and the legacy
// retirement status.
import { state, runtime } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import {
  migrationHandoffRendererAckArguments,
  normalizeBootPayload,
  normalizeRetirementStatus,
  unverifiableRetirementStatus,
} from "./migration.js";

let migrationHandoffRendererReady = null;

let criticalMigrationListenersBound = false;

function applyBootPayload(payload) {
  const normalized = normalizeBootPayload(payload);
  state.payload = { product: normalized.product, native_ui: normalized.native_ui };
  state.migrationHandoff = normalized.migration_handoff;
  state.migrationHandoffStatus = normalized.migration_handoff_status;
  if (state.migrationHandoff || state.migrationHandoffStatus.state === "in_progress") {
    state.legacyMaintenanceOpen = true;
  }
  migrationHandoffRendererReady = normalized.migration_handoff_renderer_ready;
}

export function markHandoffStatusUnverifiable(error) {
  state.migrationHandoffStatus = {
    state: "failed",
    code: "migration_handoff_task_failed",
    message: t("Migration handoff status could not be verified. Review the application log before retrying."),
  };
  appendLog("error", "migration", t("Migration handoff state could not be trusted: {error}", { error: errorText(error) }));
}

export async function loadBootPayload() {
  applyBootPayload(await invoke("boot_payload"));
}

/// The page's critical migration listeners are subscribed; the renderer may
/// acknowledge the handoff only after this.
export function markCriticalListenersBound() {
  criticalMigrationListenersBound = true;
}

export async function acknowledgeMigrationHandoffRendererReady() {
  const page = document.getElementById("page");
  const args = migrationHandoffRendererAckArguments(
    {
      migration_handoff: state.migrationHandoff,
      migration_handoff_renderer_ready: migrationHandoffRendererReady,
    },
    state.retirement,
    {
      activePage: state.activePage,
      migrationRendered: Boolean(page?.querySelector(".cfw-migration-banner")),
      globalActionsBound: runtime.globalEventsBound,
      criticalListenersBound: criticalMigrationListenersBound,
    },
  );
  if (!args) return;
  await invoke("acknowledge_migration_handoff_renderer_ready", args);
  migrationHandoffRendererReady = { state: "published" };
}

/// Reads optional maintenance and unfinished-operation status. Network start
/// admission belongs to the engine; unreadable maintenance state remains
/// visible rather than being represented as completed cleanup.
export async function loadRetirementStatus() {
  try {
    state.retirement = normalizeRetirementStatus(
      await invoke("legacy_retirement_status"), state.payload.product.operating_system,
    );
  } catch (error) {
    state.retirement = unverifiableRetirementStatus(errorText(error));
    appendLog("error", "engine", t("Unable to read the legacy retirement state: {error}", { error: errorText(error) }));
  }
}
