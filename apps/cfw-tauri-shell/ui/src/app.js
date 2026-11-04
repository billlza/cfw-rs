import { Channel } from "@tauri-apps/api/core";
import { createNativeRuntimeSettings } from "./native-runtime-settings.js";
import { createNativeGeneralSwitches } from "./native-general-switches.js";
import { createNativePromptDialog } from "./native-prompt-dialog.js";
import { createWindowGlass } from "./window-glass.js";
import { t, getLocale } from "./i18n.js";
import { defaultSettings, defaultSettingsSnapshot, THEME_OPTIONS, state, MAX_CONNECTION_ROWS, runtime, activeProfile } from "./state.js";

import { invoke, listen } from "./ipc.js";
import { escapeHtml, errorText, formatBytes, safeRegex } from "./text-format.js";
import { engineStateLabel, systemProxyValueLabel, modeHasSystemProxy, modeHasTunnel, tunnelValueLabel } from "./engine-status-model.js";
import { delayFailureLabel } from "./proxy-delay.js";
import { appendLog } from "./app-log.js";
import {
  engineIsOff,
  captureEngineIdentityToken,
  engineIdentityTokenIsCurrent,
  controllerActionAllowed,
} from "./engine-identity.js";
import {
  renderToggle,
  renderInlineSwitch,
  renderRowReason,
  renderCatLogo,
  generalIconButton,
  renderRowNote,
} from "./controls.js";
import { launchAtLoginPresentation } from "./settings-snapshot.js";
import { REASONS } from "./reasons.js";
import { createLogsView } from "./logs-view.js";
import { renderProfiles } from "./profiles-view.js";
import { renderFeedback } from "./feedback-view.js";
import { renderObservationRecheckNotice, renderStartupRecoveryNotice } from "./engine-notices.js";
import { renderMigrationBanner } from "./migration-banner.js";
import {
  loadControllerSnapshot,
  loadControllerSnapshotWithRetry,
  loadRulesSnapshot,
} from "./controller-reads.js";
import { startLiveStreams } from "./live-streams.js";
import { engineToggleCapability } from "./engine-capability.js";
import { loadNetworkDiagnostics, loadPlatformDesign } from "./system-info.js";
import { serviceProxyLabel } from "./network-diagnostics.js";
import { createProviderUI } from "./providers.js";
import { createRuntimeSettingsUI, RUNTIME_LOG_LEVELS } from "./runtime-settings.js";
import { createGeneralView } from "./general.js";
import { createProxyView } from "./proxies.js";
import { createEditingRender, createScrollKeeper } from "./editing-render.js";
import { createConnectionsView } from "./connections.js";
import { createConnectionDiagnostics } from "./connection-diagnostics.js";
import { createRulesView } from "./rules.js";
import { createSettingsView } from "./settings-view.js";
import { createAutomationSettingsUI } from "./automation-settings.js";
import { createProxyDelayTest } from "./proxy-delay-test.js";
import { createEngineStatus } from "./engine-status.js";
import { createRuntimeProjection } from "./runtime-projection.js";
import { createProfileData } from "./profile-data.js";
import { createSettingsController } from "./settings-controller.js";
import { createToggles } from "./toggles.js";
import { createControllerMutations } from "./controller-mutations.js";
import { createProxyCommands } from "./proxy-commands.js";
import { createCredentialSetup } from "./credential-setup.js";
import { createProfileMenu } from "./profile-menu.js";
import { createUpdateController } from "./update-controller.js";
import { createProfileDialogs } from "./profile-dialogs.js";
import { createDiagnosticsDialogs } from "./diagnostics-dialogs.js";
import { createLegacyMigrationDialog } from "./legacy-migration-dialog.js";
import { createGlassOverlays } from "./glass-overlays.js";
import { createMigrationActions } from "./migration-actions.js";
import { createProxyActions } from "./proxy-actions.js";
import { createEngineActions } from "./engine-actions.js";
import { createGeneralActions } from "./general-actions.js";
import { createConnectionActions } from "./connection-actions.js";
import { createLogActions } from "./log-actions.js";
import { createRuleActions } from "./rule-actions.js";
import { createProfileActions } from "./profile-actions.js";
import { createPageShell } from "./page-shell.js";
import { createGlobalEvents } from "./global-events.js";
import { createHostEvents } from "./host-events.js";
import {
  acknowledgeMigrationHandoffRendererReady,
  loadBootPayload,
  loadRetirementStatus,
  markCriticalListenersBound,
} from "./migration-session.js";

// Native presentations owned by the page. Each one reports its own failures.
const windowGlass = createWindowGlass({
  // The glass follows the main window only; a migration handoff window keeps
  // the page's own backgrounds.
  enabled: () => state.payload?.native_ui?.window_glass === true && !state.migrationHandoff,
  invoke, makeChannel: (handler) => new Channel(handler),
  doc: document, win: window, randomUUID: () => crypto.randomUUID(),
  onError: (error) => appendLog("error", "ui", t("Native window glass failed: {error}", { error: errorText(error) })),
});
const nativeRuntimeSettings = createNativeRuntimeSettings({
  enabled: () => state.payload?.native_ui?.runtime_settings === true,
  invoke, makeChannel: (handler) => new Channel(handler),
  onError: (error) => appendLog("error", "settings", t("{action} failed: {error}", { action: t("Network settings"), error: errorText(error) })),
});
const nativePromptDialog = createNativePromptDialog({
  // The host refuses presentation commands for a migration handoff window and
  // while a handoff is in progress; those dialogs stay in the page.
  enabled: () => state.payload?.native_ui?.prompt_dialog === true && !state.migrationHandoff
    && state.migrationHandoffStatus?.state !== "in_progress",
  invoke, makeChannel: (handler) => new Channel(handler),
  // The dialog's own action did not fail; only its native presentation did.
  onError: (error, title) => appendLog("error", "ui", t("Native presentation of “{title}” failed: {error}", { title, error: errorText(error) })),
});

const editingRender = createEditingRender({ document,
  requestFrame: (callback) => window.requestAnimationFrame(callback), rerender: () => renderPage() });
// A page keeps its scroll offsets across dialogs; a dialog keeps them while it stays open.
const replacePageMarkup = createScrollKeeper();
const replaceOverlayMarkup = createScrollKeeper();
const proxyView = createProxyView({ state, runtime, escapeHtml, delayFailureLabel, engineStateLabel, engineIsOff });
const {
  cancelDelayTest, slugDomId, freshProxyControllerSnapshotAvailable, activeProxyGroup, hideTimedOutProxies, renderProxies,
  changePage: changeProxyPage, revealSelected: revealSelectedProxy,
} = proxyView;
const { renderLogs, patchLogStream, scheduleLogStreamPatch } = createLogsView({ scheduleRender });

// Controllers, created after everything they use. A controller created later
// is reached through a function that runs only once startup is complete.
const { applyEngineStatus, loadEngineStatus, reconcileStartupServices } = createEngineStatus({
  renderPage, updateStatusBar, cancelDelayTest,
});
const automationSettingsUI = createAutomationSettingsUI({ state, invoke, renderPage, appendLog,
  dismissOtherDialogs: () => { dismissNativeProfileMenu(); runtimeSettingsUI.close(); state.glassDialog = null; state.profileContextMenu = null; } });

const runtimeSettingsUI = createRuntimeSettingsUI({ state, invoke, appendLog, renderPage,
  nativeDialog: nativeRuntimeSettings,
  dismissOtherDialogs: () => { dismissNativeProfileMenu(); automationSettingsUI.close(); state.glassDialog = null; state.profileContextMenu = null; },
  refreshRuntime: async () => {
    await loadEngineStatus();
    await loadRuntimeProjection();
    if (state.engine.active) await loadControllerSnapshotWithRetry(6, 300);
  },
});

const { runtimeProjectionActionAllowed, loadRuntimeProjection } = createRuntimeProjection({ runtimeSettingsUI });

const { renderProviders, loadProvidersSnapshot, bindProviderButtons, handleProviderAction,
  providerSelectionChanged } = createProviderUI({ state, invoke, appendLog, renderPage,
  refreshProfile: async () => {
    await loadProfilesSnapshot();
    await loadRuntimeProjection();
    await loadEngineStatus();
    if (state.engine.active) await loadControllerSnapshot();
  },
});

const { loadProfilesSnapshot, resolveProfileSource, invokeProfileChange, selectProfileById, applyActiveProfile } = createProfileData({
  cancelDelayTest, loadProvidersSnapshot, providerSelectionChanged, loadEngineStatus, loadRuntimeProjection,
});
const settings = createSettingsController({
  windowGlass, renderPage, renderGlassOverlays, loadProfilesSnapshot, closeGlassDialog,
});
const {
  applyPersistedSettings, resetPersistedSettingsToSafeState, persistedSettingsFromUi, loadSettingsSnapshot,
  refreshStartupLoginItemStatus,
} = settings;
const { applyUiToggle, applyToggle } = createToggles({
  renderPage, runtimeSettingsUI, applyEngineStatus, loadEngineStatus, loadRuntimeProjection,
  applyPersistedSettings, persistedSettingsFromUi, loadSettingsSnapshot,
});
const nativeGeneralSwitches = createNativeGeneralSwitches({
  enabled: () => state.payload?.native_ui?.general_switches === true && !state.migrationHandoff,
  isGeneral: () => state.activePage === "general",
  visible: () => state.activePage === "general" && !state.glassDialog && !state.runtimeSettingsDialog
    && !state.automationDialog && !state.profileInspector && !state.profileContextMenu,
  locale: getLocale, invoke, makeChannel: (handler) => new Channel(handler),
  onToggle: applyUiToggle,
  onError: (error) => {
    state.nativeGeneralPresentationError = t("{action} failed: {error}", { action: t("General"), error: errorText(error) });
    appendLog("error", "ui", state.nativeGeneralPresentationError);
    scheduleRender();
  },
});
const { enqueueControllerMutation } = createControllerMutations({ renderPage });
const { applyProxyMode, applyProxySelection } = createProxyCommands({
  renderPage, enqueueControllerMutation, freshProxyControllerSnapshotAvailable, loadProfilesSnapshot,
});
const credentialSetup = createCredentialSetup({ renderPage, renderGlassOverlays, closeGlassOverlays });
const { openCredentialSetup } = credentialSetup;
const profileMenu = createProfileMenu({
  renderPage, renderGlassOverlays, resolveProfileSource, selectProfileById, invokeProfileChange,
  loadProfilesSnapshot, openCredentialSetup,
});
const { dismissNativeProfileMenu, openProfileContextMenu, runProfileMenuAction } = profileMenu;
const updates = createUpdateController({ renderPage, renderGlassOverlays, overlayOpen, closeGlassOverlays });
const { applyUpdateInfo, invalidateUpdateAuthorization, openProductAboutDialog, updateInstall } = updates;
const profileDialogs = createProfileDialogs({
  renderPage, renderGlassOverlays, closeGlassOverlays, closeGlassDialog, loadProfilesSnapshot, invokeProfileChange,
});
const { showInvalidProfileSource } = profileDialogs;
const diagnosticsDialogs = createDiagnosticsDialogs({ renderPage, renderGlassOverlays, runtimeProjectionActionAllowed });
const legacyMigrationDialog = createLegacyMigrationDialog({
  renderPage, renderGlassOverlays, closeGlassOverlays, loadProfilesSnapshot, applyActiveProfile,
});
const overlays = createGlassOverlays({
  nativeGeneralSwitches, nativePromptDialog, runtimeSettingsUI, automationSettingsUI, replaceOverlayMarkup, profileMenu,
  providers: [
    profileDialogs.dialogs,
    credentialSetup.dialogs,
    diagnosticsDialogs.dialogs,
    legacyMigrationDialog.dialogs,
    settings.dialogs,
    updates.dialogs,
  ],
});

/// Entry points of the overlay layer. The controllers above open and close its
/// dialogs, so it is created after them and reached through these functions.
function renderGlassOverlays() { overlays.renderGlassOverlays(); }
function closeGlassOverlays() { overlays.closeGlassOverlays(); }
function closeGlassDialog(dialog) { overlays.closeGlassDialog(dialog); }
function overlayOpen() { return overlays.overlayOpen(); }

// Page views.
const connectionDiagnostics = createConnectionDiagnostics({ state, runtime, invoke, renderPage });
const { renderConnections, scheduleConnectionsPatch, bindConnectionRowEvents } = createConnectionsView({
  state, runtime, MAX_CONNECTION_ROWS, safeRegex, escapeHtml, formatBytes, renderPage, bindPageEvents,
  controllerActionAllowed, captureEngineIdentityToken, engineIdentityTokenIsCurrent, invoke, loadControllerSnapshot, appendLog, errorText,
  renderDiagnostics: connectionDiagnostics.render,
});

const { renderRules, changePage: changeRulePage } = createRulesView({state,escapeHtml});
const { renderSettings } = createSettingsView({ state, defaultSettingsSnapshot, defaultSettings, engineIsOff, launchAtLoginPresentation, escapeHtml, renderToggle, THEME_OPTIONS, REASONS, engineStateLabel, serviceProxyLabel });
const runProxyDelayTest = createProxyDelayTest({ state, runtime, view: proxyView, invoke, activeProfile, engineIsOff,
  controllerActionAllowed, captureEngineIdentityToken, engineIdentityTokenIsCurrent, appendLog, renderPage, errorText, delayFailureLabel });
const renderGeneral = createGeneralView({ state, escapeHtml, engineStateLabel, engineToggleCapability, launchAtLoginPresentation, modeHasTunnel, modeHasSystemProxy, renderMigrationBanner, renderRowReason, renderStartupRecoveryNotice, renderObservationRecheckNotice, renderCatLogo, generalIconButton, renderRowNote, renderInlineSwitch, tunnelValueLabel, systemProxyValueLabel, REASONS, RUNTIME_LOG_LEVELS });

// Actions, by feature.
const migrationActions = createMigrationActions({ renderPage, loadEngineStatus });
const proxyActions = createProxyActions({
  renderPage, activeProxyGroup, hideTimedOutProxies, revealSelectedProxy, runProxyDelayTest, changeProxyPage,
  slugDomId, cancelDelayTest, applyProxyMode, applyProxySelection,
});
const engineActions = createEngineActions({ renderPage, reconcileStartupServices, applyToggle, applyUiToggle });
const generalActions = createGeneralActions({ renderPage, renderGlassOverlays, automationSettingsUI, runtimeSettingsUI });
const connectionActions = createConnectionActions({ renderPage, bindConnectionRowEvents });
const logActions = createLogActions({ renderPage, patchLogStream });
const ruleActions = createRuleActions({ renderPage, changeRulePage });
const profileActions = createProfileActions({
  renderPage, renderGlassOverlays, scheduleRender, runProfileMenuAction, invokeProfileChange, loadProfilesSnapshot,
  selectProfileById, openCredentialSetup, resolveProfileSource, openProfileContextMenu, showInvalidProfileSource,
});
const { importProfileFromPath } = profileActions;

/// Run once per page load. What the previous installation attempt left behind
/// is logged, a failure of that attempt or of its review is also shown, and
/// an installation the host still holds is shown again.
export async function reportPreviousUpdateInstall() {
  await updateInstall.resolveOutcome();
}

const pageRenderers = {
  general: renderGeneral,
  proxies: renderProxies,
  profiles: renderProfiles,
  providers: renderProviders,
  logs: renderLogs,
  connections: renderConnections,
  rules: renderRules,
  settings: renderSettings,
  feedback: renderFeedback,
};

const pageShell = createPageShell({
  editingRender, replacePageMarkup, windowGlass, nativeGeneralSwitches, renderGlassOverlays, bindPageEvents, pageRenderers,
});
const { followWindowResize, startStatusClock } = pageShell;

/// Entry points of the page shell. It is created once every page view exists,
/// after the controllers that render through it.
function renderPage() { pageShell.renderPage(); }
function scheduleRender() { pageShell.scheduleRender(); }
function updateStatusBar() { pageShell.updateStatusBar(); }

const { bindGlobalEvents } = createGlobalEvents({
  editingRender, followWindowResize, overlayOpen, closeGlassOverlays, handleAction, applyProxyMode, applyToggle, renderPage,
  patchLogStream,
});
const {
  onPage, onSettingsChanged, onUpdateAvailable, onUpdateProgress, onConnectionsSnapshot,
  onEngineSnapshot, onEngineEvent, onLogLines, onStreamError, onDragDrop,
} = createHostEvents({
  renderPage, scheduleRender, updateStatusBar, applyPersistedSettings, loadSettingsSnapshot,
  resetPersistedSettingsToSafeState, loadEngineStatus, loadRuntimeProjection, applyUpdateInfo, openProductAboutDialog,
  updateInstall, scheduleConnectionsPatch, scheduleLogStreamPatch, importProfileFromPath,
});

/// Every page binds its own controls after it renders.
function bindPageEvents() {
  engineActions.bindPage();
  settings.bindPage();
  ruleActions.bindPage();
  proxyActions.bindPage();
  profileActions.bindPage();
  document.querySelectorAll("[data-page]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const page = event.currentTarget.dataset.page;
      if (page !== "proxies") cancelDelayTest();
      state.activePage = page;
      await invoke("open_page", { page });
      renderPage();
      if (page === "proxies") {
        await loadControllerSnapshotWithRetry(6, 400);
        renderPage();
      }
      if (page === "rules") {
        await loadRulesSnapshot();
        renderPage();
      }
    });
  });

  bindProviderButtons();

  runtimeSettingsUI.bindPage();

  document.querySelectorAll("[data-modal-stop]").forEach((modal) => {
    modal.addEventListener("click", (event) => event.stopPropagation());
  });
  logActions.bindPage();
  connectionActions.bindPage();
  connectionDiagnostics.bindPage();
  migrationActions.bindPage();
}

const MACOS_MAINTENANCE_ACTIONS = new Set([
  "open-legacy-maintenance", "close-legacy-maintenance", "begin-migration-handoff",
  "prepare-cutover", "confirm-cutover", "recover-cutover",
  "migrate-legacy-profiles",
]);

/// The actions of the window itself.
const shellActions = {
  "reload-dashboard": async () => {
    await reloadPayload();
  },
  "update-all-providers": async (action) => {
    await handleProviderAction(action);
  },
  "health-check-all": (action) => shellActions["update-all-providers"](action),
  "quit-app": async () => {
    await invoke("quit_app");
  },
  "force-quit-app": async () => {
    await invoke("force_quit_app");
  },
};

/// Every action a rendered control or a shortcut can ask for, by name.
const dashboardActions = new Map();
for (const table of [
  shellActions, migrationActions.actions, proxyActions.actions, engineActions.actions, generalActions.actions,
  connectionActions.actions, logActions.actions, ruleActions.actions, profileActions.actions,
  connectionDiagnostics.actions,
  diagnosticsDialogs.actions, legacyMigrationDialog.actions, credentialSetup.actions, settings.actions, updates.actions,
]) {
  for (const [name, run] of Object.entries(table)) {
    if (dashboardActions.has(name)) throw new TypeError(`dashboard action ${name} is defined twice`);
    dashboardActions.set(name, run);
  }
}

const WINDOWS_ACTIONS = new Set(["open-windows-startup-settings"]);

export async function handleAction(action) {
  const operatingSystem = state.payload.product.operating_system;
  if (MACOS_MAINTENANCE_ACTIONS.has(action) && operatingSystem !== "macos") {
    throw new Error("Historical Mac maintenance does not apply to this platform");
  }
  if (WINDOWS_ACTIONS.has(action) && operatingSystem !== "windows") {
    throw new Error("Windows startup settings do not apply to this platform");
  }
  const run = dashboardActions.get(action);
  if (!run) throw new Error(`Unknown dashboard action: ${action}`);
  return run(action);
}

async function reloadPayload() {
  if (!state.migrationHandoff) await loadBootPayload();
  state.lastRefresh = t("Just now");
  await loadSettingsSnapshot();
  await loadPlatformDesign();
  await loadEngineStatus();
  await loadRetirementStatus();
  await loadNetworkDiagnostics();
  await loadProfilesSnapshot();
  // The projection belongs to the active profile, so it must be re-read after
  // the profile snapshot.  Keeping the previous projection here can make the
  // General and Settings pages claim a stale port or controller endpoint.
  await loadRuntimeProjection();
  const controllerReady = await loadControllerSnapshotWithRetry();
  if (controllerReady) {
    if (state.activePage === "rules") await loadRulesSnapshot();
  }
  appendLog("info", "shell", t("Dashboard reloaded"));
  renderPage();
}

async function bootstrap() {
  bindGlobalEvents();
  await loadBootPayload();
  if (state.migrationHandoff) state.activePage = "general";

  // Paint a verified-identity shell before any optional OS or repository read.
  // A slow SystemConfiguration/Keychain/filesystem boundary must never leave
  // the WKWebView looking like a dead black window.
  renderPage();
  const networkDiagnostics = loadNetworkDiagnostics();
  const startupSettings = loadSettingsSnapshot(false);
  await Promise.all([
    startupSettings,
    loadPlatformDesign(),
    loadEngineStatus(),
    loadRetirementStatus(),
  ]);
  // Provider availability is part of the engine snapshot, so profile/provider
  // loading must remain ordered after loadEngineStatus rather than racing it.
  await loadProfilesSnapshot();
  await loadRuntimeProjection();
  renderPage();
  void networkDiagnostics.finally(() => {
    if (state.activePage === "settings") renderPage();
  });

  document.getElementById("reload-button").addEventListener("click", reloadPayload);

  await listen("cfw://page", onPage);

  await listen("cfw://settings-changed", onSettingsChanged);

  await listen("cfw://update-available", onUpdateAvailable);

  await listen("cfw://update-progress", onUpdateProgress);

  await listen("cfw://connections-snapshot", onConnectionsSnapshot);

  await listen("cfw://engine-snapshot", onEngineSnapshot);

  await listen("cfw://engine-event", onEngineEvent);

  await listen("cfw://log-lines", onLogLines);

  await listen("cfw://stream-error", onStreamError);

  await listen("tauri://drag-drop", onDragDrop);

  markCriticalListenersBound();
  // Native reconciliation can finish after the first snapshot but before the
  // event subscriptions above. Events have no replay, so close that interval
  // with one current read after both engine listeners are installed. Future
  // transitions use the listeners; reads never retry native reconciliation.
  await loadEngineStatus();
  await loadRuntimeProjection();
  renderPage();
  void (async () => {
    if (await loadControllerSnapshotWithRetry()) {
      if (state.activePage === "rules") await loadRulesSnapshot();
    }
  })().finally(renderPage);
  if (state.migrationHandoff) {
    // Close the snapshot/listener gap without requesting another boot challenge
    // in this renderer lifetime. A real WebView reload receives the next
    // parent-ticket-bound generation from its one bootstrap call.
    await loadRetirementStatus();
    renderPage();
  }
  await acknowledgeMigrationHandoffRendererReady();
  window.__CFM_STARTUP__?.ready();
  void startupSettings.then(refreshStartupLoginItemStatus);

  // The migration handoff instance has no update surface and never asks.
  if (!state.migrationHandoff) await reportPreviousUpdateInstall();

  // Register every listener before the automatic check. The setup-time check
  // used to race this subscription and could lose the only availability event.
  if (state.toggles.checkForUpdates) {
    try {
      applyUpdateInfo(await invoke("check_for_updates"));
    } catch (error) {
      appendLog("error", "updater", t("Automatic update check failed: {error}", { error: errorText(error) }));
      invalidateUpdateAuthorization(error);
    }
  }

  await startLiveStreams();

  startStatusClock();
}

export function renderFatalBootstrap() {
  if (window.__CFM_STARTUP__) {
    window.__CFM_STARTUP__.fail();
    return;
  }
  document.body.innerHTML = `<pre class="fatal">${escapeHtml(t("The application could not start safely (startup_state_unverifiable). Review the application log before retrying."))}</pre>`;
}

bootstrap().catch(() => {
  renderFatalBootstrap();
});
