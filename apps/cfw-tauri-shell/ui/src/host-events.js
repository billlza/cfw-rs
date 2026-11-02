// The page's reactions to the events the host emits: page changes, settings,
// update availability, engine state, the live streams and dropped files.
import { state, runtime } from "./state.js";
import { errorText } from "./text-format.js";
import { summarizeEngineEvent } from "./engine-status-model.js";
import { t } from "./i18n.js";
import { appendLog, appendLogLines } from "./app-log.js";
import { validatedStreamEventPayload } from "./engine-identity.js";
import { applyConnectionsSnapshot } from "./controller-snapshot.js";
import { loadControllerSnapshotWithRetry } from "./controller-reads.js";
import { startLiveStreams } from "./live-streams.js";
import { isProfileSourcePath } from "./profile-import.js";
import { loadBootPayload, loadRetirementStatus, markHandoffStatusUnverifiable } from "./migration-session.js";

export function createHostEvents({
  renderPage, scheduleRender, updateStatusBar, applyPersistedSettings, loadSettingsSnapshot,
  resetPersistedSettingsToSafeState, loadEngineStatus, loadRuntimeProjection, applyUpdateInfo, openProductAboutDialog,
  updateInstall, scheduleConnectionsPatch, scheduleLogStreamPatch, importProfileFromPath,
}) {
  const onPage = (event) => {
    state.activePage = event.payload;
    renderPage();
  };

  const onSettingsChanged = async (event) => {
    try {
      applyPersistedSettings(event.payload);
    } catch (error) {
      appendLog("error", "settings", t("Rejected an invalid settings update: {error}", { error: errorText(error) }));
      try {
        await loadSettingsSnapshot();
        appendLog("warning", "settings", t("Preferences were recovered from the native store after an invalid update event."));
      } catch (refreshError) {
        resetPersistedSettingsToSafeState();
        state.settingsUnavailableReason = t("Preferences are unavailable because the native settings snapshot could not be verified. Reload from disk before changing them.");
        appendLog("error", "settings", t("Native settings recovery failed: {error}", { error: errorText(refreshError) }));
      }
    }
    await loadEngineStatus();
    await loadRuntimeProjection();
    renderPage();
  };

  const onUpdateAvailable = (event) => {
    applyUpdateInfo(event.payload);
    if (state.glassDialog?.kind === "product-about") {
      openProductAboutDialog({
        autoCheck: true,
        phase: "idle",
        result: event.payload,
      });
    }
    if (state.activePage === "general" || state.activePage === "settings" || state.activePage === "feedback") {
      renderPage();
    }
  };

  const onUpdateProgress = (event) => updateInstall.onProgress(event.payload);

  const onConnectionsSnapshot = (event) => {
    if (state.connectionPaused) return;
    const payload = validatedStreamEventPayload(
      event.payload,
      runtime.connectionsLiveStream.binding,
      "connections",
    );
    if (payload === undefined) return;
    applyConnectionsSnapshot(payload);
    // Only the status bar and the Connections page show snapshot data. Every
    // other page keeps its DOM, so controls stay attached between snapshots.
    updateStatusBar();
    if (state.activePage === "connections") scheduleConnectionsPatch();
  };

  // Emitted with no payload when the legacy-retirement gate changes what the
  // engine is allowed to do, so the capability reason on General is re-read
  // instead of going stale.
  const onEngineSnapshot = async () => {
    await loadEngineStatus();
    await loadRetirementStatus();
    await startLiveStreams();
    renderPage();
  };

  const onEngineEvent = async (event) => {
    const payload = event.payload ?? {};
    if (payload.type === "snapshot_changed") {
      await loadEngineStatus();
      await loadRuntimeProjection();
      if (state.engine.active) await loadControllerSnapshotWithRetry(2, 400);
      await startLiveStreams();
      renderPage();
      return;
    }
    if (typeof payload.code === "string" && payload.code.startsWith("migration_handoff_")) {
      if (!state.migrationHandoff) {
        try {
          await loadBootPayload();
        } catch (error) {
          markHandoffStatusUnverifiable(error);
        }
      }
      renderPage();
    }
    appendLog("error", "engine", summarizeEngineEvent(payload));
    if (state.activePage === "logs") scheduleLogStreamPatch();
  };

  const onLogLines = (event) => {
    if (state.logsPaused) return;
    const payload = validatedStreamEventPayload(
      event.payload,
      runtime.logLiveStream.binding,
      "request-logs",
    );
    if (payload === undefined) return;
    appendLogLines(payload);
    if (state.activePage === "logs") scheduleLogStreamPatch();
  };

  const onStreamError = (event) => {
    const envelope = event.payload;
    const stream = envelope?.provenance?.stream;
    const binding = stream === "connections"
      ? runtime.connectionsLiveStream.binding
      : stream === "request-logs"
        ? runtime.logLiveStream.binding
        : null;
    const payload = validatedStreamEventPayload(envelope, binding, stream);
    if (payload === undefined || payload?.stream !== stream) return;
    const level = payload.level ?? "error";
    appendLog(level, payload.stream ?? "stream", payload.message ?? "stream unavailable");
    if (state.activePage === "logs") {
      scheduleLogStreamPatch();
    } else if (state.activePage === "connections") {
      scheduleRender();
    }
  };

  const onDragDrop = async (event) => {
    const paths = event.payload?.paths ?? [];
    const profilePaths = paths.filter(isProfileSourcePath);
    if (!profilePaths.length) {
      if (paths.length) {
        appendLog("warning", "profile", t("Drag-drop requires a JSON, YAML, or node-link text profile"));
      }
      return;
    }
    for (const path of profilePaths) {
      await importProfileFromPath(path);
    }
  };

  return {
    onPage, onSettingsChanged, onUpdateAvailable, onUpdateProgress, onConnectionsSnapshot,
    onEngineSnapshot, onEngineEvent, onLogLines, onStreamError, onDragDrop,
  };
}
