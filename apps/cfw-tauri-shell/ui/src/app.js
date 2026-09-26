import { Channel } from "@tauri-apps/api/core";
import { profileMenuItems, nativeMenuItems, createNativeProfileMenu } from "./native-profile-menu.js";
import { createNativeRuntimeSettings } from "./native-runtime-settings.js";
import { createNativeGeneralSwitches } from "./native-general-switches.js";
import { t, setLocale, getLocale, SUPPORTED_LOCALES, LANGUAGE_OPTIONS } from "./i18n.js";
import {
  PAGES,
  defaultEngineStatus,
  defaultSettings,
  defaultSettingsSnapshot,
  FONT_OPTIONS,
  THEME_OPTIONS,
  state,
  primaryNavIds,
  MAX_CONNECTION_ROWS,
  MAX_LOG_ROWS,
  runtime,
} from "./state.js";

import {
  sleep,
  invoke,
  listen,
  escapeHtml,
  errorText,
  formatRuntime,
  engineStateLabel,
  normalizeEngineStatus,
  summarizeEngineEvent,
  systemProxyValueLabel,
  modeHasSystemProxy,
  modeHasTunnel,
  tunnelValueLabel,
  formatBytes,
  formatRate,
  formatRelativeUpdated,
  delayFailureLabel,
  latestDelay,
  logEntry,
  withLogRow,
  withLogRows,
  normalizeLevel,
  safeRegex,
  pageById,
  activeProfile,
} from "./format.js";

import {
  credentialLabel,
  credentialProvisionBatch,
  normalizeCredentialGcPreview,
  normalizeCredentialPresence,
  normalizeCredentialReferences,
  normalizeCredentialReceipt,
  normalizeGcReceipt,
} from "./credentials.js";

import { savedProfilePolicy } from "./profile-policy.js";

import {
  PROFILE_SOURCE_ACCEPT,
  isProfileSourcePath,
  isSubscriptionSource,
  readProfileSourceFile,
} from "./profile-import.js";

import {
  clearCutoverReceipt,
  cutoverConfirmArguments,
  cutoverReceiptIsCurrent,
  legacyMaintenanceRoute,
  migrationHandoffRendererAckArguments,
  newCutoverState,
  normalizeBootPayload,
  normalizeCutoverPreparation,
  normalizeLegacyProfileMigrationOutcome,
  normalizeLegacyProfileMigrationPreview,
  normalizeRetirementStatus,
  unverifiableRetirementStatus,
} from "./migration.js";

let migrationHandoffRendererReady = null;
let criticalMigrationListenersBound = false;
const nativeProfileMenu = createNativeProfileMenu({ invoke, makeChannel: (handler) => new Channel(handler), onError: reportProfileMenuFailure });
const nativeRuntimeSettings = createNativeRuntimeSettings({
  enabled: () => state.payload?.native_ui?.runtime_settings === true,
  invoke, makeChannel: (handler) => new Channel(handler),
  onError: (error) => appendLog("error", "settings", t("{action} failed: {error}", { action: t("Network settings"), error: errorText(error) })),
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

function nativeProfileMenuEnabled() { return state.payload?.native_ui?.profile_menu === true; }
function reportProfileMenuFailure(error) {
  appendLog("error", "profile", t("{action} failed: {error}", { action: t("Profiles"), error: errorText(error) }));
}
function dismissNativeProfileMenu() {
  if (nativeProfileMenuEnabled()) void nativeProfileMenu.dismiss().catch(reportProfileMenuFailure);
}

const LOGIN_ITEM_LIVE_STATUSES = new Set([
  "checking",
  "enabled",
  "not_registered",
  "not_found",
  "requires_approval",
  "unknown",
]);
const SETTINGS_FIELDS = Object.freeze([
  "check_for_updates",
  "font_family",
  "language",
  "launch_at_login",
  "retain_window_bounds",
  "silent_start",
  "theme",
]);

/// Reasons the dashboard shows next to a control the 0.4.0 backend refuses.
/// Each one states what the product does instead, so a disabled switch is never
/// unexplained and never silently does nothing.
const REASONS = Object.freeze({
  get allowLan() { return t("LAN sharing uses a separate listener restricted to explicitly trusted private source networks."); },
  get bindAddress() { return t("The local proxy and controller stay on loopback. LAN devices use their own listener address and port."); },
  get logLevel() { return t("Changes apply through a validated runtime replacement and are saved for the next launch."); },
  get mixin() { return t("Mixin is unavailable: the engine configuration is projected by the app, and an imported document may only describe routing and outbound policy."); },
  get geoip() { return t("Country rules use sing-box rule sets, downloaded on first start and refreshed daily while the engine runs. An existing Clash Country.mmdb file is not used."); },
  get restoreDns() { return t("This app never writes host DNS, because the legacy restore value carries no per-service ownership identity. Clear or set custom DNS per service in System Settings › Network › Details › DNS."); },
  get engineNotOff() { return t("Stop the core before credential maintenance or legacy migration."); },
});


/// Applies a `SettingsSnapshot`. The preference store holds exactly seven
/// renderer-owned fields; everything the 0.3.5 file used to carry now lives in
/// the projected engine configuration and is read, never written, from there.
import { createProviderUI } from "./providers.js";
import { createRuntimeSettingsUI, RUNTIME_LOG_LEVELS } from "./runtime-settings.js";
import { createGeneralView } from "./general.js";
import { createProxyView } from "./proxies.js";
import { createEditingRender } from "./editing-render.js";
const editingRender = createEditingRender({ document,
  requestFrame: (callback) => window.requestAnimationFrame(callback), rerender: () => renderPage() });
const proxyView = createProxyView({ state, runtime, escapeHtml, delayFailureLabel, engineStateLabel, engineIsOff });
const { delayClass, delayLabel, delayConcurrency, cancelDelayTest, visibleProxyNodeNames, orderNamesVisibleFirst, applyDelayToProxyNodes, patchProxyDelayLabels, finalizeDelayTestNames, slugDomId, isManualProxyGroup, freshProxyControllerSnapshotAvailable, displayedProxyGroups, activeProxyGroup, hideTimedOutProxies, renderProxies, modeIcon, changePage: changeProxyPage, revealSelected: revealSelectedProxy } = proxyView;

import { createConnectionsView } from "./connections.js";
const { renderConnections, scheduleConnectionsPatch, connectionFacets, bindConnectionRowEvents } = createConnectionsView({
  state, runtime, MAX_CONNECTION_ROWS, safeRegex, escapeHtml, formatBytes, renderPage, bindPageEvents,
  controllerActionAllowed, captureEngineIdentityToken, engineIdentityTokenIsCurrent, invoke, loadControllerSnapshot, appendLog, errorText,
});

import { createRulesView } from "./rules.js";
const { renderRules, changePage: changeRulePage } = createRulesView({state,escapeHtml});
import { createSettingsView } from "./settings-view.js";
const { renderSettings, renderNetworkDiagnostics } = createSettingsView({ state, defaultSettingsSnapshot, defaultSettings, engineIsOff, launchAtLoginPresentation, escapeHtml, renderToggle, THEME_OPTIONS, FONT_OPTIONS, REASONS, engineStateLabel, serviceProxyLabel });

import { createAutomationSettingsUI } from "./automation-settings.js";
const automationSettingsUI = createAutomationSettingsUI({ state, invoke, renderPage, appendLog,
  dismissOtherDialogs: () => { dismissNativeProfileMenu(); runtimeSettingsUI.close(); state.glassDialog = null; state.profileContextMenu = null; } });

import { createProxyDelayTest } from "./proxy-delay-test.js";
const runProxyDelayTest = createProxyDelayTest({ state, runtime, view: proxyView, invoke, activeProfile, engineIsOff,
  controllerActionAllowed, captureEngineIdentityToken, engineIdentityTokenIsCurrent, appendLog, renderPage, errorText, delayFailureLabel });
const renderGeneral = createGeneralView({ state, escapeHtml, engineStateLabel, engineToggleCapability, launchAtLoginPresentation, modeHasTunnel, modeHasSystemProxy, renderMigrationBanner, renderRowReason, renderCatLogo, generalIconButton, renderRowNote, renderInlineSwitch, tunnelValueLabel, systemProxyValueLabel, REASONS, RUNTIME_LOG_LEVELS });

const runtimeSettingsUI = createRuntimeSettingsUI({ state, invoke, appendLog, renderPage,
  nativeDialog: nativeRuntimeSettings,
  dismissOtherDialogs: () => { dismissNativeProfileMenu(); automationSettingsUI.close(); state.glassDialog = null; state.profileContextMenu = null; },
  refreshRuntime: async () => {
    await loadEngineStatus();
    await loadRuntimeProjection();
    if (state.engine.active) await loadControllerSnapshotWithRetry(6, 300);
  },
});

const { renderProviders, loadProvidersSnapshot, bindProviderButtons, handleProviderAction,
  providerSelectionChanged } = createProviderUI({ state, invoke, appendLog, renderPage,
  refreshProfile: async () => {
    await loadProfilesSnapshot();
    await loadRuntimeProjection();
    await loadEngineStatus();
    if (state.engine.active) await loadControllerSnapshot();
  },
});

function applyPersistedSettings(snapshot) {
  const settings = normalizeSettingsSnapshot(snapshot);
  const launchAtLogin = normalizeLaunchAtLoginState(snapshot);
  state.settingsSnapshot = snapshot;
  state.settingsUnavailableReason = null;
  state.launchAtLogin = launchAtLogin;
  state.toggles.startAtLogin = launchAtLogin.liveStatus === "enabled"
    || launchAtLogin.liveStatus === "requires_approval";
  state.toggles.silentStart = Boolean(settings.silent_start);
  state.toggles.checkForUpdates = Boolean(settings.check_for_updates);
  state.toggles.retainWindowBounds = Boolean(settings.retain_window_bounds);
  applyAppearance(settings);
  setLocale(snapshot.resolved_locale);
  window.__CFM_STARTUP__?.setLanguage?.(snapshot.resolved_locale);
  localizeShell();
}

function resetPersistedSettingsToSafeState() {
  state.settingsSnapshot = {
    persisted: defaultSettingsSnapshot.persisted,
    resolved_locale: getLocale(),
    settings: { ...defaultSettingsSnapshot.settings },
    launch_at_login: { ...defaultSettingsSnapshot.launch_at_login },
  };
  state.launchAtLogin = {
    persistedIntent: false,
    liveStatus: "unknown",
    matchesPersistedIntent: false,
  };
  state.toggles.startAtLogin = false;
  state.toggles.silentStart = false;
  state.toggles.checkForUpdates = false;
  state.toggles.retainWindowBounds = defaultSettings.retain_window_bounds;
  applyAppearance(defaultSettings);
}

function normalizeSettingsSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    throw new TypeError("settings snapshot is not an object");
  }
  const snapshotFields = Object.keys(snapshot).sort();
  if (snapshotFields.join("\0") !== ["launch_at_login", "persisted", "resolved_locale", "settings"].join("\0")) {
    throw new TypeError("settings snapshot field set is invalid");
  }
  if (typeof snapshot.persisted !== "boolean") {
    throw new TypeError("settings persisted flag is not boolean");
  }
  const settings = snapshot.settings;
  if (!settings || typeof settings !== "object" || Array.isArray(settings)) {
    throw new TypeError("settings snapshot omitted typed preferences");
  }
  if (Object.keys(settings).sort().join("\0") !== SETTINGS_FIELDS.join("\0")) {
    throw new TypeError("settings preference field set is invalid");
  }
  if (!THEME_OPTIONS.some((option) => option.value === settings.theme)) {
    throw new TypeError("settings theme is invalid");
  }
  if (!FONT_OPTIONS.some((option) => option.value === settings.font_family)) {
    throw new TypeError("settings font family is invalid");
  }
  if (!LANGUAGE_OPTIONS.some((option) => option.value === settings.language)
      || !SUPPORTED_LOCALES.includes(snapshot.resolved_locale)
      || (settings.language !== "system" && settings.language !== snapshot.resolved_locale)) {
    throw new TypeError("settings display language is invalid");
  }
  for (const field of [
    "retain_window_bounds",
    "launch_at_login",
    "silent_start",
    "check_for_updates",
  ]) {
    if (typeof settings[field] !== "boolean") {
      throw new TypeError(`settings ${field} is not boolean`);
    }
  }
  return settings;
}

function normalizeLaunchAtLoginState(snapshot) {
  const value = snapshot?.launch_at_login;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("settings snapshot omitted the typed Login Item state");
  }
  if (Object.keys(value).sort().join("\0") !== [
    "live_status",
    "matches_persisted_intent",
    "persisted_intent",
  ].join("\0")) {
    throw new TypeError("Login Item state field set is invalid");
  }
  if (typeof value.persisted_intent !== "boolean") {
    throw new TypeError("Login Item persisted intent is not boolean");
  }
  if (!LOGIN_ITEM_LIVE_STATUSES.has(value.live_status)) {
    throw new TypeError("Login Item live status is invalid");
  }
  if (typeof value.matches_persisted_intent !== "boolean") {
    throw new TypeError("Login Item synchronization flag is not boolean");
  }
  if (value.persisted_intent !== snapshot.settings.launch_at_login) {
    throw new TypeError("Login Item persisted intent disagrees with settings");
  }
  const expectedMatch = value.live_status === "enabled"
    ? value.persisted_intent
    : value.live_status === "not_registered" || value.live_status === "not_found"
      ? !value.persisted_intent
      : false;
  if (value.matches_persisted_intent !== expectedMatch) {
    throw new TypeError("Login Item synchronization flag disagrees with live status");
  }
  return {
    persistedIntent: value.persisted_intent,
    liveStatus: value.live_status,
    matchesPersistedIntent: value.matches_persisted_intent,
  };
}

function launchAtLoginPresentation() {
  if (state.settingsUnavailableReason) {
    return {
      hint: state.settingsUnavailableReason,
      reason: state.settingsUnavailableReason,
    };
  }
  const value = state.launchAtLogin;
  if (value.observationError) {
    return { hint: value.observationError, reason: value.observationError };
  }
  if (value.liveStatus === "checking") {
    const reason = t("Checking macOS Login Item status…");
    return { hint: reason, reason };
  }
  if (value.liveStatus === "unknown") {
    const reason = t("Start at Login is unavailable because macOS returned an unknown Login Item state.");
    return { hint: reason, reason };
  }
  if (value.liveStatus === "requires_approval") {
    return {
      hint: "macOS requires approval in System Settings › General › Login Items. Approve it there, or switch Off to cancel registration.",
      reason: null,
    };
  }
  if (!value.matchesPersistedIntent) {
    if (value.liveStatus === "enabled") {
      return {
        hint: "macOS currently enables this Login Item, while the saved preference says Off. Switching Off reconciles both states.",
        reason: null,
      };
    }
    const status = value.liveStatus === "not_found" ? t("cannot find the signed app") : t("reports it is not registered");
    return {
      hint: t("The saved preference says On, but macOS {status}. Switching On retries registration without silently changing the preference.", { status: status }),
      reason: null,
    };
  }
  return {
    hint: value.liveStatus === "enabled"
      ? t("Enabled by macOS and requested by the saved preference.")
      : t("Disabled by macOS and by the saved preference."),
    reason: null,
  };
}

/// The seven renderer-owned preference fields, and nothing else: the preference
/// store rejects an unknown field, and `launch_at_login` may only be changed by
/// the transactional Login Item command, so it is echoed back unchanged.
function persistedSettingsFromUi() {
  const current = state.settingsSnapshot?.settings ?? defaultSettings;
  const theme = document.querySelector("[data-theme-setting]")?.value ?? current.theme ?? "system";
  const fontFamily = document.querySelector("[data-font-family]")?.value ?? current.font_family ?? "";
  const language = document.querySelector("[data-language-setting]")?.value ?? current.language;
  if (!LANGUAGE_OPTIONS.some((option) => option.value === language)) throw new TypeError("Invalid language preference");
  return {
    theme: THEME_OPTIONS.some((option) => option.value === theme) ? theme : "system",
    font_family: FONT_OPTIONS.some((option) => option.value === fontFamily) ? fontFamily : "",
    language,
    retain_window_bounds: state.toggles.retainWindowBounds,
    launch_at_login: Boolean(current.launch_at_login),
    silent_start: state.toggles.silentStart,
    check_for_updates: state.toggles.checkForUpdates,
  };
}

function applyAppearance(settings) {
  const requested = settings.theme === "dark" || settings.theme === "light" ? settings.theme : "system";
  const resolved = requested === "system"
    ? (window.matchMedia?.("(prefers-color-scheme: dark)")?.matches ? "dark" : "light")
    : requested;
  document.documentElement.dataset.theme = resolved;
  const font = String(settings.font_family ?? "").trim();
  document.documentElement.style.setProperty(
    "--sans",
    font ? `"${font}", "Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif` : '"Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif',
  );
}

function localizeShell() {
  document.querySelectorAll("[data-i18n]").forEach((element) => { element.textContent = t(element.dataset.i18n); });
  const nav = document.getElementById("nav");
  nav?.setAttribute("aria-label", t("Primary navigation"));
  const reload = document.getElementById("reload-button");
  reload?.setAttribute("title", t("Reload dashboard"));
}

function applyControllerSnapshot(snapshot) {
  if (!snapshot) return;

  const config = snapshot.config ?? {};
  const mode = config.mode ? config.mode[0].toUpperCase() + config.mode.slice(1).toLowerCase() : null;
  state.mode = ["Global", "Rule", "Direct"].includes(mode) ? mode : null;
  // Clash API describes the loopback inbound. LAN sharing has its own listener
  // and source policy, whose state comes from the runtime settings transaction.
  state.toggles.allowLan = state.runtimeSettings?.settings.allow_lan ?? false;
  state.logLevel = config["log-level"] ?? config.log_level ?? null;

  const proxyNodes = new Map((snapshot.proxies?.proxies ?? []).map((node) => [node.name, node]));
  const groups = snapshot.proxies?.groups ?? [];
  const groupsByName = new Map(groups.map((group) => [group.name, group]));
  const previousDelays = new Map();
  if (state.toggles.testingDelays) {
    state.proxyGroups.forEach((group) => {
      group.options.forEach((node) => {
        previousDelays.set(node.name, node.delay);
      });
    });
  }
  // Always replace — empty groups must clear stale iKuuu UI after a failed/empty profile.
  state.proxyGroups = groups.map((group) => {
    const projectNode = (name) => {
      const node = proxyNodes.get(name);
      const nestedGroup = groupsByName.get(name);
      let delay = latestDelay(node?.history ?? nestedGroup?.history ?? []);
      if (state.toggles.testingDelays && previousDelays.has(name)) {
        // Keep in-flight Pending / partial results while a delay test runs.
        delay = previousDelays.get(name);
      }
      const measured = state.proxyDelayResults.get(name);
      return {
        name,
        label: state.savedProfilePolicy?.nodeLabels?.[name] ?? name,
        delay: measured ? measured.delay : delay,
        delayFailure: measured?.delayFailure ?? null,
        dead: Boolean(measured?.delayFailure),
        kind: node?.kind ?? node?.type ?? nestedGroup?.kind ?? group.kind ?? "Proxy",
        udp: node?.udp ?? null,
      };
    };
    const options = (group.options ?? []).map(projectNode);
    const observedOption = options.length === 0
      && !isManualProxyGroup(group.kind)
      && typeof group.now === "string"
      && proxyNodes.has(group.now)
      ? projectNode(group.now)
      : null;
    return {
      name: group.name,
      type: group.kind,
      now: group.now ?? group.options?.[0] ?? "DIRECT",
      options,
      observedOption,
    };
  });

  applyConnectionsSnapshot(snapshot.connections);
  state.controllerStatus = "controller live";
}

function applyConnectionsSnapshot(snapshot) {
  if (!snapshot) return;

  const now = Date.now();
  const elapsed = state.connectionStream.at ? Math.max(0.25, (now - state.connectionStream.at) / 1000) : 0;
  const uploadTotal = snapshot.upload ?? snapshot.uploadTotal ?? snapshot.upload_total ?? 0;
  const downloadTotal = snapshot.download ?? snapshot.downloadTotal ?? snapshot.download_total ?? 0;
  const previousRows = state.connectionStream.rows ?? new Map();
  const connections = snapshot.connections ?? [];
  state.connections = connections.map((connection) => {
    const metadata = connection.metadata ?? {};
    const host = metadata.host || metadata.destinationIP || metadata.destination_ip || "unknown";
    const rulePayload = connection.rulePayload ?? connection.rule_payload;
    const rule = [connection.rule, rulePayload].filter(Boolean).join(",");
    const previous = previousRows.get(connection.id);
    const uploadBytes = connection.upload ?? 0;
    const downloadBytes = connection.download ?? 0;
    const uploadSpeed = previous && elapsed ? Math.max(0, (uploadBytes - previous.upload) / elapsed) : 0;
    const downloadSpeed = previous && elapsed ? Math.max(0, (downloadBytes - previous.download) / elapsed) : 0;
    return {
      id: connection.id,
      host,
      rule: rule || "MATCH",
      chains: connection.chains ?? [],
      upload: formatBytes(uploadBytes),
      download: formatBytes(downloadBytes),
      uploadBytes,
      downloadBytes,
      uploadSpeedBytes: uploadSpeed,
      downloadSpeedBytes: downloadSpeed,
      speed: `${formatBytes(uploadSpeed)}/s up · ${formatBytes(downloadSpeed)}/s down`,
      age: connection.start ? connection.start.slice(11, 19) : "live",
      start: connection.start,
      metadata,
    };
  });

  if (elapsed) {
    state.traffic.upload = Math.max(0, (uploadTotal - state.connectionStream.uploadTotal) / elapsed / 1024 / 1024);
    state.traffic.download = Math.max(0, (downloadTotal - state.connectionStream.downloadTotal) / elapsed / 1024 / 1024);
  }
  state.connectionStream = {
    at: now,
    uploadTotal,
    downloadTotal,
    rows: new Map(connections.map((connection) => [connection.id, { upload: connection.upload, download: connection.download }])),
  };
  state.controllerStatus = "controller live stream";
}


function visibleLogs() {
  const regex = safeRegex(state.logSearch);
  return state.logs.filter((line) => {
    const level = normalizeLevel(line.level);
    const matchesLevel = state.logFilter === "all" || level === state.logFilter;
    const haystack = [line.time, level, line.source, line.message, ...(line.fields ?? []).map((field) => `${field.key}=${field.value}`)].join(" ");
    const matchesSearch = !state.logSearch || (regex ? regex.test(haystack) : haystack.toLowerCase().includes(state.logSearch.toLowerCase()));
    return matchesLevel && matchesSearch;
  }).slice(0, MAX_LOG_ROWS);
}

function renderLogStreamHtml() {
  const logs = visibleLogs();
  return logs.map((line) => `
          <article class="log-line ${escapeHtml(line.level)}">
            <time>${escapeHtml(line.time)}</time>
            <b>${escapeHtml(line.level)}</b>
            <span>${escapeHtml(line.source)}</span>
            <p>
              ${escapeHtml(line.message)}
              ${(line.fields ?? []).length ? `<small>${line.fields.map((field) => `${escapeHtml(field.key)}=${escapeHtml(field.value)}`).join(" · ")}</small>` : ""}
            </p>
          </article>
        `).join("") || `<p class="empty">${escapeHtml(t("No logs for this filter."))}</p>`;
}

function logCountLabel(visibleCount) {
  return t("Log entries: {visible} / {total}", { visible: visibleCount, total: state.logs.length })
    + (state.logsPaused ? ` · ${t("Paused")}` : "");
}

function patchLogStream() {
  const stream = document.querySelector(".log-stream");
  if (!stream) return false;
  const heading = document.querySelector(".logs-layout .toolbar-panel h3");
  if (heading) {
    heading.textContent = logCountLabel(visibleLogs().length);
  }
  stream.innerHTML = renderLogStreamHtml();
  return true;
}

function scheduleLogStreamPatch() {
  if (runtime.logStreamFrame !== null) return;
  runtime.logStreamFrame = window.requestAnimationFrame(() => {
    runtime.logStreamFrame = null;
    if (state.activePage !== "logs") return;
    if (!patchLogStream()) scheduleRender();
  });
}

function renderNav() {
  const nav = document.getElementById("nav");
  nav.innerHTML = PAGES
    .filter((page) => primaryNavIds.has(page.id))
    .map((page, index) => {
      const active = page.id === state.activePage ? " active" : "";
      return `
        <button class="nav-item${active}" data-page="${escapeHtml(page.id)}">
          <span>${index + 1}</span>
          <b>${escapeHtml(t(page.title))}</b>
        </button>
      `;
    })
    .join("");
}

/// A switch row. `options.reason` marks the switch unavailable and states why,
/// both in the row and in the control's own tooltip.
function renderToggle(key, label, hint, options = {}) {
  const reason = options.reason ?? null;
  const allowDisableWhenUnavailable = options.allowDisableWhenUnavailable === true;
  const checkedState = Boolean(state.toggles[key]);
  const disabled = options.disabled || (reason && !(allowDisableWhenUnavailable && checkedState));
  const checked = (!reason || allowDisableWhenUnavailable) && checkedState ? "checked" : "";
  return `
    <label class="toggle-row ${disabled ? "disabled" : ""}">
      <span>
        <b>${escapeHtml(label)}</b>
        <small>${escapeHtml(reason ?? hint)}</small>
      </span>
      <input type="checkbox" data-toggle="${escapeHtml(key)}" ${checked} ${disabled ? "disabled" : ""} ${reason ? `title="${escapeHtml(reason)}"` : ""} />
      <i></i>
    </label>
  `;
}

function renderInlineSwitch(key, label, options = {}) {
  const reason = options.reason ?? null;
  const allowDisableWhenUnavailable = options.allowDisableWhenUnavailable === true;
  const checkedState = Boolean(state.toggles[key]);
  const disabled = options.disabled || (reason && !(allowDisableWhenUnavailable && checkedState));
  const checked = (!reason || allowDisableWhenUnavailable) && checkedState ? "checked" : "";
  const title = reason ?? options.title ?? null;
  return `
    <label class="inline-switch ${disabled ? "disabled" : ""}" ${title ? `title="${escapeHtml(title)}"` : ""}>
      <span class="visually-hidden">${escapeHtml(label)}${title ? ` — ${escapeHtml(title)}` : ""}</span>
      <input type="checkbox" data-toggle="${escapeHtml(key)}" ${checked} ${disabled ? "disabled" : ""} />
      <i></i>
    </label>
  `;
}

/// Explanation line under a General row whose control the backend refuses.
function renderRowReason(reason) {
  return `
    <div class="cfw-row cfw-row-reason">
      <div class="cfw-row-left"><small>${escapeHtml(reason)}</small></div>
      <div class="cfw-row-right"></div>
    </div>
  `;
}

function renderCatLogo() {
  return `
    <svg class="cfw-cat-logo" viewBox="0 0 112 96" aria-hidden="true">
      <path d="M23 86c-12 0-19-8-19-17 0-9 7-15 16-15 4 0 7 1 10 3l4-43 17 16 12-1 18-17 6 72c-17 2-40 2-64 2Z" />
      <path class="cat-tail" d="M22 70c-14 4-24-4-20-15 2-6 8-9 13-7" />
      <circle cx="43" cy="45" r="4" />
      <circle cx="71" cy="45" r="4" />
      <path class="cat-mouth" d="M54 58c3 3 6 3 9 0" />
    </svg>
  `;
}

function renderStatusPill(label, value, tone = "neutral") {
  return `
    <div class="status-pill ${tone}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `;
}


function generalIcon(kind) {
  const common = 'width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"';
  switch (kind) {
    case "terminal":
      return `<svg ${common}><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm1 3v2l3 2-3 2v2l5-3.5L5 7zm7 8h6v2h-6v-2z"/></svg>`;
    case "sync":
      return `<svg ${common}><path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46A7.93 7.93 0 0 0 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74A7.93 7.93 0 0 0 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/></svg>`;
    case "sync-off":
      return `<svg ${common}><path d="M20 12c0-4.42-3.58-8-8-8V1L8 5l1.7 1.7C12.9 6.8 15.2 8.9 16.1 11.5l1.7 1.7c.13-.4.2-.8.2-1.2zM4.27 3 3 4.27l2.05 2.05A7.95 7.95 0 0 0 4 12c0 4.42 3.58 8 8 8v3l4-4-1.3-1.3L19.73 21 21 19.73 4.27 3zM12 18c-3.31 0-6-2.69-6-6 0-1.3.41-2.5 1.11-3.48L14.48 16.9A5.9 5.9 0 0 1 12 18z"/></svg>`;
    case "info":
      return `<svg ${common}><path d="M12 2a10 10 0 1 0 .001 20.001A10 10 0 0 0 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>`;
    case "device-hub":
      return `<svg ${common}><path d="M17 16h-2v-2h2v2zm-4 0h-2v-2h2v2zm-4 0H7v-2h2v2zm10-6h-2V8h2v2zm-4 0h-2V8h2v2zm-4 0H7V8h2v2zm10-6H5c-1.1 0-2 .9-2 2v14h18V6c0-1.1-.9-2-2-2zm0 14H5V6h14v10z"/></svg>`;
    case "memory":
      return `<svg ${common}><path d="M15 9H9v6h6V9zm-2 4h-2v-2h2v2zm8-2V9h-2V7c0-1.1-.9-2-2-2h-2V3h-2v2h-2V3H9v2H7c-1.1 0-2 .9-2 2v2H3v2h2v2H3v2h2v2c0 1.1.9 2 2 2h2v2h2v-2h2v2h2v-2h2c1.1 0 2-.9 2-2v-2h2v-2h-2v-2h2zm-4 6H7V7h10v10z"/></svg>`;
    case "dns":
      return `<svg ${common}><path d="M20 13H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM20 3H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>`;
    case "play":
      return `<svg ${common}><path d="M8 5v14l11-7L8 5z"/></svg>`;
    case "public":
      return `<svg ${common}><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>`;
    case "settings":
      return `<svg ${common}><path d="M19.14 12.94c.04-.31.06-.63.06-.94s-.02-.63-.06-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.49.49 0 0 0-.59-.22l-2.39.96a7.2 7.2 0 0 0-1.62-.94l-.36-2.54A.48.48 0 0 0 14 2h-4a.48.48 0 0 0-.48.42l-.36 2.54c-.59.24-1.13.56-1.62.94l-2.39-.96a.49.49 0 0 0-.59.22L2.65 8.87a.49.49 0 0 0 .12.61l2.03 1.58c-.04.31-.06.63-.06.94s.02.63.06.94L2.77 14.52a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.42.48.42h4c.24 0 .44-.18.48-.42l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32a.49.49 0 0 0-.12-.61l-2.01-1.58zM12 15.5A3.5 3.5 0 1 1 12 8.5a3.5 3.5 0 0 1 0 7z"/></svg>`;
    case "history":
      return `<svg ${common}><path d="M13 3a9 9 0 0 0-9 9H1l3.89 3.89.07.14L9 12H6a7 7 0 0 1 7-7 7 7 0 0 1 7 7 7 7 0 0 1-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42A8.95 8.95 0 0 0 13 21a9 9 0 0 0 0-18zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>`;
    default:
      return "";
  }
}

function generalIconButton(action, kind, title, options = {}) {
  const tone = options.tone ? ` ${options.tone}` : "";
  const active = options.active ? " active" : "";
  return `<button type="button" class="general-icon${tone}${active}" data-action="${escapeHtml(action)}" title="${escapeHtml(title)}">${generalIcon(kind)}</button>`;
}

function applyUpdateInfo(payload) {
  if (!payload || typeof payload !== "object") return;
  state.updateInfo = {
    available: Boolean(payload.available),
    current: payload.current ?? state.payload?.product?.version,
    version: payload.version ?? null,
    notes: payload.notes ?? null,
    date: payload.date ?? null,
    error: payload.error ?? null,
  };
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


/// Which proxy slots one macOS network service currently has enabled, whoever
/// owns them. Ownership is not reported, so it is not claimed.
function serviceProxyLabel(service) {
  const enabled = [
    service?.web?.enabled ? "HTTP" : null,
    service?.secure_web?.enabled ? "HTTPS" : null,
    service?.socks?.enabled ? "SOCKS" : null,
    service?.pac_enabled ? "PAC" : null,
    service?.wpad_enabled ? "WPAD" : null,
  ].filter(Boolean);
  return enabled.length ? enabled.join(", ") : "off";
}

/// A short note plus the backend's full reason, shown next to a control the
/// product cannot honour.
function renderRowNote(short, reason) {
  return `<small class="cfw-row-note" title="${escapeHtml(reason)}">${escapeHtml(short)}</small>`;
}

/// Optional maintenance for older Clash for Mac installations.
///
/// Settings exposes the controlled restart into the `--migration-handoff`
/// instance. Existing unfinished transactions keep their recovery surface.
/// Destructive actions retain their explicit preparation and confirmation.
function renderMigrationBanner() {
  const retirement = state.retirement;
  if (!retirement || typeof retirement.state !== "string") return "";
  const route = legacyMaintenanceRoute(
    retirement, state.migrationHandoff, state.legacyMaintenanceOpen,
  );
  if (route === "none") return "";
  const close = state.legacyMaintenanceOpen && !state.migrationHandoff
    && legacyMaintenanceRoute(retirement, false) === "none"
    ? `<button type="button" class="cfw-text-button" data-action="close-legacy-maintenance">${escapeHtml(t("Close maintenance"))}</button>`
    : "";
  if (route === "complete") {
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>${escapeHtml(t("Legacy CFM maintenance is complete"))}</strong>
          <small>${escapeHtml(t("No legacy cleanup is pending."))}</small>
          ${close}
        </div>
      </div>
    `;
  }
  let cutover = state.cutover;
  if (cutover.receiptId && !cutoverReceiptIsCurrent(cutover)) {
    state.cutover = clearCutoverReceipt(cutover, {
      message: t("The cutover preparation expired. Prepare the replacement again."),
    });
    cutover = state.cutover;
  }

  if (route === "unverifiable") {
    return `
      <div class="cfw-migration-banner cfw-migration-unverifiable" role="alert">
        <div class="cfw-migration-copy">
          <strong>${escapeHtml(t("Legacy CFM maintenance state cannot be verified"))}</strong>
          <small>${escapeHtml(retirement.message ?? t("The legacy operation state could not be read. Reload before requesting maintenance."))}</small>
        </div>
      </div>
    `;
  }

  if (route === "busy") {
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>${escapeHtml(t("Legacy CFM maintenance is in progress"))}</strong>
          <small>${escapeHtml(t("The confirmed legacy operation must finish before another network start."))}</small>
        </div>
      </div>
    `;
  }

  if (route === "launch_prepare" || route === "launch_recovery") {
    const recovery = route === "launch_recovery";
    const handoffStatus = state.migrationHandoffStatus;
    const starting = handoffStatus?.state === "in_progress";
    const failure = handoffStatus?.state === "failed" ? handoffStatus.message : null;
    const profileUnavailable = !recovery && state.profilesUnavailableReason;
    const selectedProfileMissing = !recovery
      && !profileUnavailable
      && !state.profiles.some((profile) => profile.active === true);
    const detail = starting
      ? "The signed maintenance session is starting. This dashboard closes after the new window is ready and the current CFM engine is safely Off."
      : recovery
        ? "Review and resume the previous legacy CFM operation in its signed maintenance session."
        : profileUnavailable
          ? t("Profile state could not be verified: {profileUnavailable}. Open Profiles and reload it before legacy maintenance.", { profileUnavailable: profileUnavailable })
          : selectedProfileMissing
            ? "Import and select a replacement profile on Profiles before retiring older CFM components. Normal networking uses the System Proxy and TUN switches."
            : t("Optional maintenance retires older Clash for Mac components and managed data. Opening its signed session stops the current CFM engine and closes this dashboard; retirement still requires a separate confirmation. Use the network switches for normal starts.");
    const button = starting
      ? t("Starting…")
      : failure
        ? (recovery ? t("Retry Recovery…") : t("Retry Maintenance…"))
        : (profileUnavailable || selectedProfileMissing)
          ? t("Open Profiles")
          : (recovery ? t("Open Recovery…") : t("Open Legacy Maintenance…"));
    const action = profileUnavailable || selectedProfileMissing
      ? "open-migration-profiles"
      : "begin-migration-handoff";
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>${starting ? t("Legacy CFM maintenance session is starting") : recovery ? t("Legacy CFM recovery") : t("Optional legacy CFM maintenance")}</strong>
          <small>${escapeHtml(detail)}</small>
          ${retirement.message ? `<small>${escapeHtml(retirement.message)}</small>` : ""}
          ${failure ? `<small>${escapeHtml(failure)}</small>` : ""}
          ${starting ? "" : close}
        </div>
        <button type="button" class="cfw-big-button" data-action="${action}" ${starting ? "disabled" : ""}>${button}</button>
      </div>
    `;
  }

  if (route === "recover") {
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>${escapeHtml(t("Recover the legacy CFM operation"))}</strong>
          <small>${escapeHtml(retirement.message ?? t("The unfinished legacy transaction requires explicit recovery."))}</small>
          ${cutover.message ? `<small>${escapeHtml(cutover.message)}</small>` : ""}
        </div>
        <button type="button" class="cfw-big-button" data-action="recover-cutover" ${cutover.busy ? "disabled" : ""}>${cutover.busy ? "Recovering…" : t("Recover Replacement")}</button>
      </div>
    `;
  }

  const target = cutover.target;
  const targetLabel = target === "tunnel" ? t("TUN") : t("System Proxy");
  const ready = cutoverReceiptIsCurrent(cutover);
  const step = ready
    ? `
        <label class="cfw-migration-confirm">
          <input type="checkbox" data-cutover-confirm ${cutover.confirmedReceiptId === cutover.receiptId ? "checked" : ""} />
          <span>${escapeHtml(t("I understand this one-way cutover retires older CFM components and managed data and cannot be undone."))}</span>
        </label>
        <label class="cfw-migration-confirm">
          <input type="checkbox" data-cutover-dns-review ${cutover.dnsReviewedReceiptId === cutover.receiptId ? "checked" : ""} />
          <span>${escapeHtml(t("I have reviewed DNS for every active service in System Settings."))}</span>
        </label>
        <button type="button" class="cfw-big-button danger" data-action="confirm-cutover" ${cutover.busy ? "disabled" : ""}>${cutover.busy ? t("Migrating…") : t("Confirm one-way cutover to {value1}", { value1: escapeHtml(targetLabel) })}</button>
      `
    : `
        <button type="button" class="cfw-big-button" data-action="prepare-cutover" ${cutover.busy ? "disabled" : ""}>${cutover.busy ? "Preparing…" : t("Prepare cutover to {value1}", { value1: escapeHtml(targetLabel) })}</button>
      `;
  const approvalNote = cutover.awaitingApproval
    ? `<small>${escapeHtml(t("System Extension approval is required in System Settings. Approve it, then Prepare again."))}</small>`
    : "";
  return `
    <div class="cfw-migration-banner" role="status">
      <div class="cfw-migration-copy">
        <strong>${escapeHtml(t("Legacy CFM maintenance session"))}</strong>
        <small>${escapeHtml(t("This optional operation retires older Clash for Mac components and starts the selected replacement mode. Prepare validates that operation; retirement requires your explicit confirmation."))}</small>
        <label class="cfw-migration-target">
          <span>${escapeHtml(t("Replacement"))}</span>
          <select data-cutover-target ${ready || cutover.busy ? "disabled" : ""}>
            <option value="system_proxy" ${target === "system_proxy" ? "selected" : ""}>${escapeHtml(t("System Proxy"))}</option>
            <option value="tunnel" ${target === "tunnel" ? "selected" : ""}>${escapeHtml(t("TUN"))}</option>
          </select>
        </label>
        ${retirement.message ? `<small>${escapeHtml(retirement.message)}</small>` : ""}
        ${cutover.message ? `<small>${escapeHtml(cutover.message)}</small>` : ""}
        ${approvalNote}
      </div>
      ${step}
    </div>
  `;
}


function queueLiveStreamChange(lane, running, commands) {
  lane.desiredRunning = running;
  lane.intentEpoch += 1;
  const intentEpoch = lane.intentEpoch;
  const operation = lane.operation.then(async () => {
    if (intentEpoch !== lane.intentEpoch) return false;
    if (!running) {
      const token = captureEngineIdentityToken();
      const expected = lane.binding;
      lane.binding = null;
      if (expected) await commands.stop(expected);
      return intentEpoch === lane.intentEpoch
        && (expected === null || engineIdentityTokenIsCurrent(token));
    }

    const token = captureEngineIdentityToken();
    if (!engineIdentityTokenIsCurrent(token)) return false;
    const response = await commands.start();
    const binding = normalizeStreamBinding(response, commands.stream, token.runtimeIdentity);
    if (intentEpoch !== lane.intentEpoch || !engineIdentityTokenIsCurrent(token)) {
      if (!lane.desiredRunning) await commands.stop(binding);
      return false;
    }
    lane.binding = binding;
    return true;
  });
  lane.operation = operation.catch(() => {});
  return operation;
}

function setConnectionsStreamRunning(running) {
  return queueLiveStreamChange(runtime.connectionsLiveStream, running, {
    stream: "connections",
    start: () => invoke("start_connections_stream"),
    stop: (expected) => invoke("stop_connections_stream", { expected }),
  });
}

function setLogStreamRunning(running) {
  return queueLiveStreamChange(runtime.logLiveStream, running, {
    stream: "request-logs",
    start: () => invoke("start_log_stream"),
    stop: (expected) => invoke("stop_log_stream", { expected }),
  });
}

/// CFW profile context-menu items, in the 0.3.5 order and chrome.
///
/// `remoteOnly` items need the profile's subscription URL, which a profile list
/// deliberately never publishes. Opening the menu reads the single profile, so
/// the URL is known here; when that read fails the item is shown disabled with
/// the reason instead of being hidden.
const PROFILE_MENU_ACTIONS = [
  { id: "select", get label() { return t("Select"); }, icon: "check", needsInactive: true },
  { id: "edit", get label() { return t("Edit"); }, icon: "edit" },
  { id: "edit-external", get label() { return t("Edit externally"); }, icon: "edit" },
  { id: "update", get label() { return t("Update"); }, icon: "refresh", remoteOnly: true },
  { id: "reveal", get label() { return t("Show in folder"); }, icon: "folder" },
  { id: "outbounds", get label() { return t("Edit outbounds section"); }, icon: "send" },
  { id: "route", get label() { return t("Edit route section"); }, icon: "rules" },
  { id: "copy", get label() { return t("Copy"); }, icon: "copy" },
  { id: "qrcode", label: "QRCode", icon: "qr", remoteOnly: true },
  { id: "credentials", get label() { return t("Credentials"); }, icon: "gear", needsEngineOff: true },
  { id: "settings", get label() { return t("Settings"); }, icon: "gear" },
  { id: "delete", get label() { return t("Delete"); }, icon: "trash", danger: true },
];

function profileMenuIcon(kind) {
  const icons = {
    check: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9.2 16.6 4.8 12.2l1.4-1.4 3 3 8.6-8.6 1.4 1.4-10 10z"/></svg>`,
    home: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 3.2 3.8 10.2v9.6h5.4v-5.4h5.6v5.4h5.4v-9.6L12 3.2z"/></svg>`,
    edit: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4.5 16.9 15.8 5.6l2.6 2.6L7.1 19.5H4.5v-2.6zm14.3-11.7 1.5 1.5c.4.4.4 1 0 1.4l-1.2 1.2-2.6-2.6 1.2-1.2c.4-.4 1-.4 1.4 0z"/></svg>`,
    refresh: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 5a7 7 0 0 1 6.3 4H16v2h5.5V5.5H19v1.7A9 9 0 1 0 21 12h-2a7 7 0 1 1-7-7z"/></svg>`,
    folder: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3.5 6.5A2 2 0 0 1 5.5 4.5h4l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2v-11z"/></svg>`,
    diff: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M7 4h2v5H7V4zm0 11h2v5H7v-5zm8-7.5 3.5 3.5L15 14.5V12h-4v-2h4V7.5zM5 10h6v2H5v-2z"/></svg>`,
    send: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3.2 11.2 20 3.5 12.3 20.8l-1.7-6.4-7.4-3.2zm4.4 2.3 4.2 1.8 3.3-7.4-7.5 5.6z"/></svg>`,
    rules: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M5 5h14v2H5V5zm0 6h14v2H5v-2zm0 6h10v2H5v-2z"/></svg>`,
    copy: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M8 7h10v12H8V7zm-3 3H4V4h11v2H5v4zm3-1h2v10h8v2H8V9z"/></svg>`,
    qr: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4 4h7v7H4V4zm2 2v3h3V6H6zm7-2h7v7h-7V4zm2 2v3h3V6h-3zM4 13h7v7H4v-7zm2 2v3h3v-3H6zm9 0h2v2h-2v-2zm4 0h2v2h-2v-2zm-4 4h2v2h-2v-2zm2 2h4v2h-4v-2zm2-4h2v4h-2v-4z"/></svg>`,
    tree: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M10 3h4v4h-4V3zm-5 7h4v4H5v-4zm10 0h4v4h-4v-4zM7 13h2v3h6v-3h2v5H7v-5z"/></svg>`,
    code: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m8.2 7.2 1.4 1.4L6.8 12l2.8 3.4-1.4 1.4L4 12l4.2-4.8zm7.6 0L20 12l-4.2 4.8-1.4-1.4 2.8-3.4-2.8-3.4 1.4-1.4z"/></svg>`,
    gear: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M11 3h2l.4 2.2a6.8 6.8 0 0 1 1.8.8l2-1.1 1.4 1.4-1.1 2a6.8 6.8 0 0 1 .8 1.8L20.5 11v2l-2.2.4a6.8 6.8 0 0 1-.8 1.8l1.1 2-1.4 1.4-2-1.1a6.8 6.8 0 0 1-1.8.8L13 20.5h-2l-.4-2.2a6.8 6.8 0 0 1-1.8-.8l-2 1.1-1.4-1.4 1.1-2a6.8 6.8 0 0 1-.8-1.8L3.5 13v-2l2.2-.4a6.8 6.8 0 0 1 .8-1.8l-1.1-2 1.4-1.4 2 1.1a6.8 6.8 0 0 1 1.8-.8L11 3zm1 6.5A2.5 2.5 0 1 0 12 14a2.5 2.5 0 0 0 0-5z"/></svg>`,
    trash: `<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9 4h6l1 2h4v2H4V6h4l1-2zm1 5h2v9h-2V9zm4 0h2v9h-2V9zM7 9h2v9H7V9z"/></svg>`,
  };
  return icons[kind] ?? icons.gear;
}

function closeGlassOverlays() {
  dismissNativeProfileMenu();
  runtimeSettingsUI.close();
  automationSettingsUI.close();
  state.profileContextMenu = null;
  state.glassDialog = null;
  renderGlassOverlays();
}

/// Destructive credential maintenance still requires a complete core stop.
function engineIsOff() {
  return state.engine.state === "Off" && state.engine.desiredMode === "off";
}

function engineToggleCapability(key) {
  if ((key === "coreRunning" || key === "systemProxy" || key === "tunMode") && state.migrationHandoff) {
    return {
      available: false,
      label: key === "coreRunning" ? t("Core") : key === "systemProxy" ? t("System Proxy") : t("TUN Mode"),
      reason: t("This window owns legacy CFM maintenance. Use its explicit maintenance or recovery controls."),
    };
  }
  if (key === "coreRunning") {
    return {
      available: state.engine.localProxyAvailable === true,
      label: t("Core"),
      reason: state.engine.availabilityReason ?? t("The signed ProxyAgent has not reported local proxy capability."),
    };
  }
  if (key === "systemProxy") {
    return {
      available: state.engine.systemProxyAvailable === true,
      get label() { return t("System Proxy"); },
      reason: state.engine.availabilityReason
        ?? t("The signed ProxyAgent has not reported capability."),
    };
  }
  if (key === "tunMode") {
    return {
      available: state.engine.tunnelAvailable === true,
      get label() { return t("TUN Mode"); },
      reason: state.engine.availabilityReason
        ?? t("The signed Packet Tunnel System Extension has not reported capability."),
    };
  }
  return null;
}

/// Enabling a native network mode requires the corresponding verified
/// capability. Disabling an already-requested mode is always admitted so a
/// failed or newly unavailable target never traps the switch On.
function engineToggleChangeAllowed(key, checked, source) {
  const capability = engineToggleCapability(key);
  if (capability && state.migrationHandoff) {
    appendLog("info", source, capability.reason);
    return false;
  }
  if (!capability || !checked || capability.available) return true;
  appendLog("info", source, t("{label} cannot be enabled: {reason}", { label: capability.label, reason: capability.reason }));
  return false;
}

/// Every controller-backed mutation/inspection must use the verified runtime
/// identity, never desired mode. Engine Off is an expected state, so the guard
/// records no warning/error and, most importantly, emits no controller IPC.
function controllerActionAllowed(action, source = "controller") {
  if (state.engine.active) return true;
  state.controllerStatus = "engine off";
  appendLog("info", source, t("{action} is unavailable while the engine is Off", { action: action }));
  return false;
}

/// Runtime projection is an offline operation owned by the selected profile,
/// not by the loopback controller. Repository failure and an actually empty
/// selection remain distinct fail-closed reasons.
function runtimeProjectionActionAllowed(action, source = "profile") {
  if (state.profilesUnavailableReason) {
    appendLog("error", source, t("{action} is unavailable because the profile repository could not be read: {profilesUnavailableReason}", { action: action, profilesUnavailableReason: state.profilesUnavailableReason }));
    return false;
  }
  if (!state.profiles.some((profile) => profile.active === true)) {
    appendLog("info", source, t("{action} requires a selected profile", { action: action }));
    return false;
  }
  return true;
}

function captureEngineIdentityToken() {
  if (!state.engine.active) return null;
  return Object.freeze({
    epoch: runtime.engineIdentityEpoch,
    generation: state.engine.generation,
    configDigest: state.engine.configDigest,
    runtimeIdentity: state.engine.runtimeIdentity,
  });
}

function runtimeIdentitiesEqual(left, right) {
  return left !== null
    && right !== null
    && left?.owner === right?.owner
    && left?.ready === true
    && right?.ready === true
    && left?.context?.installation_id === right?.context?.installation_id
    && left?.context?.config_epoch === right?.context?.config_epoch
    && left?.context?.generation === right?.context?.generation
    && left?.config_digest === right?.config_digest;
}

function engineIdentityTokenIsCurrent(token) {
  return token !== null
    && state.engine.active
    && token.epoch === runtime.engineIdentityEpoch
    && token.generation === state.engine.generation
    && token.configDigest === state.engine.configDigest
    && runtimeIdentitiesEqual(token.runtimeIdentity, state.engine.runtimeIdentity);
}

function engineRuntimeIdentityChanged(previous, next) {
  return previous.active !== next.active
    || previous.generation !== next.generation
    || previous.configDigest !== next.configDigest
    || previous.mode !== next.mode
    || (previous.active && next.active
      && !runtimeIdentitiesEqual(previous.runtimeIdentity, next.runtimeIdentity));
}

function streamBindingsEqual(left, right) {
  return left !== null
    && right !== null
    && left?.stream === right?.stream
    && left?.stream_id === right?.stream_id
    && runtimeIdentitiesEqual(left?.runtime, right?.runtime);
}

function normalizeStreamBinding(value, expectedStream, expectedRuntime = state.engine.runtimeIdentity) {
  if (!value
    || typeof value !== "object"
    || value.stream !== expectedStream
    || !Number.isSafeInteger(value.stream_id)
    || value.stream_id < 1
    || !runtimeIdentitiesEqual(value.runtime, expectedRuntime)) {
    throw new TypeError(`${expectedStream} stream binding does not match the active engine runtime`);
  }
  return Object.freeze({
    stream: expectedStream,
    stream_id: value.stream_id,
    runtime: expectedRuntime,
  });
}

function streamBindingIsCurrent(binding, expectedStream) {
  return binding !== null
    && binding?.stream === expectedStream
    && state.engine.active
    && runtimeIdentitiesEqual(binding?.runtime, state.engine.runtimeIdentity);
}

function validatedStreamEventPayload(envelope, binding, expectedStream) {
  if (!streamBindingIsCurrent(binding, expectedStream)
    || !envelope
    || typeof envelope !== "object"
    || !Object.hasOwn(envelope, "payload")
    || !streamBindingsEqual(envelope.provenance, binding)) {
    return undefined;
  }
  return envelope.payload;
}

function controllerModeFromSnapshot(snapshot) {
  const value = snapshot?.config?.mode;
  if (typeof value !== "string" || !value.length) return null;
  const mode = value[0].toUpperCase() + value.slice(1).toLowerCase();
  return ["Global", "Rule", "Direct"].includes(mode) ? mode : null;
}

function controllerSelectorFromSnapshot(snapshot, groupName) {
  const group = (snapshot?.proxies?.groups ?? []).find((item) => item?.name === groupName);
  if (!group) return null;
  if (typeof group.now === "string") return group.now;
  if (typeof group.options?.[0] === "string") return group.options[0];
  return "DIRECT";
}

function controllerMutationIsCurrent(entry) {
  return engineIdentityTokenIsCurrent(entry.token)
    && runtime.controllerMutationLatestByLane.get(entry.lane) === entry.epoch;
}

function applyPendingControllerIntents() {
  for (const pending of runtime.controllerMutationPendingByLane.values()) {
    if (!engineIdentityTokenIsCurrent(pending.token)) continue;
    if (pending.kind === "mode") {
      state.mode = pending.target;
      continue;
    }
    const group = state.proxyGroups.find((item) => item.name === pending.groupName);
    if (group) group.now = pending.target;
  }
}

function invalidateControllerMutationIntents() {
  runtime.controllerMutationLatestByLane.clear();
  runtime.controllerMutationPendingByLane.clear();
  const queued = runtime.controllerMutationQueue.splice(0);
  for (const entry of queued) entry.resolve(false);
}

function finishControllerMutationEntry(entry, result) {
  if (runtime.controllerMutationLatestByLane.get(entry.lane) === entry.epoch) {
    runtime.controllerMutationLatestByLane.delete(entry.lane);
  }
  if (runtime.controllerMutationPendingByLane.get(entry.lane)?.epoch === entry.epoch) {
    runtime.controllerMutationPendingByLane.delete(entry.lane);
  }
  entry.resolve(result);
  renderPage();
}

async function drainControllerMutationQueue() {
  if (runtime.controllerMutationRunning) return;
  runtime.controllerMutationRunning = true;
  try {
    while (runtime.controllerMutationQueue.length) {
      const entry = runtime.controllerMutationQueue.shift();
      if (!controllerMutationIsCurrent(entry)) {
        entry.resolve(false);
        continue;
      }

      let mutationError = null;
      try {
        await entry.invokeMutation();
      } catch (error) {
        mutationError = error;
      }
      if (!controllerMutationIsCurrent(entry)) {
        entry.resolve(false);
        continue;
      }

      let observedSnapshot = null;
      const controllerReadable = await loadControllerSnapshot(
        false,
        entry.token,
        () => controllerMutationIsCurrent(entry),
        (snapshot) => { observedSnapshot = snapshot; },
      );
      if (!controllerMutationIsCurrent(entry)) {
        entry.resolve(false);
        continue;
      }

      const observed = controllerReadable ? entry.readObserved(observedSnapshot) : null;
      const confirmed = controllerReadable && observed === entry.target;
      if (runtime.controllerMutationPendingByLane.get(entry.lane)?.epoch === entry.epoch) {
        runtime.controllerMutationPendingByLane.delete(entry.lane);
      }
      if (!confirmed && controllerReadable) entry.publishObserved(observed);
      applyPendingControllerIntents();

      if (mutationError) {
        const readback = controllerReadable
          ? t("controller readback reports {value1}", { value1: observed ?? "unavailable" })
          : "controller readback was unavailable";
        appendLog("error", entry.source, `${entry.failureLabel}: ${errorText(mutationError)}; ${readback}`);
        finishControllerMutationEntry(entry, false);
        continue;
      }
      if (!controllerReadable) {
        appendLog("error", entry.source, t("{failureLabel}: controller readback was unavailable", { failureLabel: entry.failureLabel }));
        finishControllerMutationEntry(entry, false);
        continue;
      }
      if (!confirmed) {
        appendLog("error", entry.source, t("{failureLabel}: controller readback reported {value2}", { failureLabel: entry.failureLabel, value2: observed ?? "unavailable" }));
        finishControllerMutationEntry(entry, false);
        continue;
      }

      if (state.toggles.breakOnProxyChange) {
        await closeConnectionsAfterProxyChange(
          entry.breakConnectionsReason,
          entry.token,
          () => controllerMutationIsCurrent(entry),
        );
      }
      if (!controllerMutationIsCurrent(entry)) {
        entry.resolve(false);
        continue;
      }
      appendLog("info", entry.source, entry.successMessage);
      finishControllerMutationEntry(entry, true);
    }
  } finally {
    runtime.controllerMutationRunning = false;
    if (runtime.controllerMutationQueue.length) void drainControllerMutationQueue();
  }
}

function enqueueControllerMutation(specification) {
  const token = captureEngineIdentityToken();
  if (!engineIdentityTokenIsCurrent(token)) return Promise.resolve(false);
  const epoch = runtime.controllerMutationEpoch + 1;
  runtime.controllerMutationEpoch = epoch;
  const pending = {
    epoch,
    token,
    lane: specification.lane,
    kind: specification.kind,
    target: specification.target,
    groupName: specification.groupName ?? null,
  };
  runtime.controllerMutationLatestByLane.set(specification.lane, epoch);
  runtime.controllerMutationPendingByLane.set(specification.lane, pending);
  applyPendingControllerIntents();
  renderPage();

  return new Promise((resolve) => {
    runtime.controllerMutationQueue.push({ ...specification, ...pending, resolve });
    void drainControllerMutationQueue();
  });
}

function invalidateEngineBoundState(active) {
  runtime.engineIdentityEpoch += 1;
  invalidateControllerMutationIntents();
  for (const lane of [runtime.connectionsLiveStream, runtime.logLiveStream]) {
    lane.intentEpoch += 1;
    lane.desiredRunning = false;
    lane.binding = null;
  }
  cancelDelayTest();
  state.proxyDelayResults.clear();
  state.proxyDelayMessage = null;
  clearControllerBackedState();
  state.controllerVersion = null;
  state.controllerStatus = active ? "controller loading" : "engine off";
}


async function resolveProfileSource(id) {
  const profile = state.profiles.find((item) => item.id === id);
  if (!profile) return undefined;
  if (profile.sourceUrl !== undefined) return profile.sourceUrl;
  try {
    const text = await invoke("read_profile_text", { id });
    profile.sourceUrl = text?.source_url ?? null;
    profile.sourceError = null;
  } catch (error) {
    profile.sourceError = errorText(error);
    appendLog("error", "profile", t("Could not read {name} source metadata: {sourceError}", { name: profile.name, sourceError: profile.sourceError }));
  }
  return profile.sourceUrl;
}

function currentProfileMenuItems(profile) {
  return profileMenuItems(PROFILE_MENU_ACTIONS, profile, { engineOff: engineIsOff(), engineNotOffReason: REASONS.engineNotOff, t });
}

function nativeProfileMenuRequest(context, profile) {
  return { requestId: context.requestId, revision: context.revision, locale: getLocale(),
    appearance: document.documentElement.dataset.theme,
    moreLabel: t("scroll to view more"), point: context.point, items: nativeMenuItems(currentProfileMenuItems(profile)) };
}

async function acceptNativeProfileMenu(context, result) {
  if (state.profileContextMenu !== context) return;
  state.profileContextMenu = null;
  if (result.error) { reportProfileMenuFailure(result.error); renderPage(); return; }
  if (result.action === null) return;
  const profile = state.profiles.find((item) => item.id === context.id);
  const action = profile && currentProfileMenuItems(profile).find((item) => item.id === result.action);
  if (!action || action.reason) {
    reportProfileMenuFailure(action?.reason ?? "The profile action is no longer available");
    renderPage(); return;
  }
  try { await runProfileMenuAction(result.action, context.id); }
  catch (error) { reportProfileMenuFailure(error); }
  renderPage();
}

async function openProfileContextMenu(id, clientX, clientY) {
  state.glassDialog = null;
  const context = { id, x: clientX, y: clientY };
  state.profileContextMenu = context;
  if (nativeProfileMenuEnabled()) {
    const profile = state.profiles.find((item) => item.id === id);
    if (!profile) { state.profileContextMenu = null; return; }
    Object.assign(context, { requestId: crypto.randomUUID(), revision: 1, ready: false,
      point: { x: clientX, y: clientY, viewportWidth: window.innerWidth, viewportHeight: window.innerHeight } });
    try {
      const request = nativeProfileMenuRequest(context, profile);
      context.projection = JSON.stringify({ locale: request.locale, appearance: request.appearance, items: request.items });
      context.ready = await nativeProfileMenu.present(request, (result) => {
        void acceptNativeProfileMenu(context, result).catch(reportProfileMenuFailure);
      });
      if (state.profileContextMenu !== context) return;
      await resolveProfileSource(id);
      if (state.profileContextMenu === context) renderGlassOverlays();
    } catch (error) {
      if (state.profileContextMenu === context) {
        state.profileContextMenu = null;
        dismissNativeProfileMenu();
      }
      reportProfileMenuFailure(error);
    }
    return;
  }
  renderGlassOverlays();
  await resolveProfileSource(id);
  if (state.profileContextMenu === context) renderGlassOverlays();
}

function syncNativeProfileMenu() {
  const context = state.profileContextMenu;
  if (!context?.ready || !context.requestId) return;
  const profile = state.profiles.find((item) => item.id === context.id);
  if (!profile || state.activePage !== "profiles" || state.glassDialog || state.runtimeSettingsDialog || state.automationDialog) {
    dismissNativeProfileMenu();
    state.profileContextMenu = null;
    return;
  }
  const request = nativeProfileMenuRequest(context, profile);
  const projection = JSON.stringify({ locale: request.locale, appearance: request.appearance, items: request.items });
  if (projection === context.projection) return;
  context.projection = projection;
  request.revision = ++context.revision;
  void nativeProfileMenu.update(request).catch((error) => {
    if (state.profileContextMenu !== context) return;
    state.profileContextMenu = null;
    dismissNativeProfileMenu();
    reportProfileMenuFailure(error);
  });
}


function renderGlassOverlays() {
  // Dialogs also render independently of renderPageContent (for example,
  // network services). Invalidate native input before replacing any overlay.
  nativeGeneralSwitches.beforeRender();
  if (nativeProfileMenuEnabled()) syncNativeProfileMenu();
  const root = document.getElementById("glass-menu-root");
  if (!root) return;

  const parts = [];
  if (state.profileContextMenu && !nativeProfileMenuEnabled()) {
    const profile = state.profiles.find((item) => item.id === state.profileContextMenu.id);
    if (profile) {
      const items = currentProfileMenuItems(profile);
      const menuHtml = items.map((action) => `
        <button type="button" class="glass-menu-item ${action.danger ? "danger" : ""}" data-profile-menu="${action.id}" data-profile-id="${escapeHtml(profile.id)}" ${action.reason ? `disabled title="${escapeHtml(action.reason)}"` : ""}>
          <span class="glass-menu-icon">${profileMenuIcon(action.icon)}</span>
          <span>${escapeHtml(action.label)}</span>
        </button>
      `).join("");
      parts.push(`
        <div class="glass-menu-backdrop" data-glass-dismiss></div>
        <div class="glass-menu" role="menu" style="left:${Math.round(state.profileContextMenu.x)}px;top:${Math.round(state.profileContextMenu.y)}px">
          <div class="glass-menu-scroll" data-glass-menu-scroll>
            ${menuHtml}
          </div>
          <div class="glass-menu-more" data-glass-menu-more hidden>
            <span>${escapeHtml(t("scroll to view more"))}</span>
            <span aria-hidden="true">▾</span>
          </div>
        </div>
      `);
    }
  }

  if (state.glassDialog) {
    const dialog = state.glassDialog;
    const profile = dialog.id ? state.profiles.find((item) => item.id === dialog.id) : null;
    if (profile && dialog.kind === "copy") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Copy profile"))}">
          <h3>${escapeHtml(t("Copy profile"))}</h3>
          <label>${escapeHtml(t("Name"))}<input data-glass-copy-name value="${escapeHtml(t("{name} copy", { name: profile.name }))}" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Cancel"))}</button>
            <button type="button" class="glass-btn" data-glass-copy-confirm="${escapeHtml(profile.id)}">${escapeHtml(t("Copy"))}</button>
          </div>
        </div>
      `);
    } else if (profile && dialog.kind === "settings") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Edit profile information"))}">
          <h3>${escapeHtml(t("Edit profile information"))}</h3>
          <label>${escapeHtml(t("Name"))}<input data-glass-settings-name value="${escapeHtml(profile.name)}" /></label>
          <label>URL<input data-glass-settings-url value="${escapeHtml(profile.sourceUrl ?? "")}" placeholder="https://..." /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Cancel"))}</button>
            <button type="button" class="glass-btn" data-glass-settings-confirm="${escapeHtml(profile.id)}">${escapeHtml(t("Save"))}</button>
          </div>
        </div>
      `);
    } else if (profile && dialog.kind === "delete") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Delete profile"))}">
          <h3>${escapeHtml(t("Delete profile"))}</h3>
          <p class="glass-dialog-copy">${escapeHtml(t("Delete “{name}”? This removes the managed profile from the repository.", { name: profile.name }))}</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("No"))}</button>
            <button type="button" class="glass-btn danger" data-glass-delete-confirm="${escapeHtml(profile.id)}">${escapeHtml(t("Yes"))}</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "reset-settings") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Reset settings"))}">
          <h3>${escapeHtml(t("Reset all settings"))}</h3>
          <p class="glass-dialog-copy">${escapeHtml(t("Reset appearance, silent start and update preferences to their defaults? Imported profiles, the selected profile and the Start with macOS registration are all kept."))}</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("No"))}</button>
            <button type="button" class="glass-btn danger" data-glass-reset-confirm>${escapeHtml(t("Yes"))}</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "preview-config") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="${escapeHtml(t("Projected configuration preview"))}">
          <h3>${escapeHtml(t("Projected configuration"))}</h3>
          <p class="glass-dialog-copy">${escapeHtml(t("The selected profile projected for the current mode. The app-owned controller secret is redacted."))}</p>
          <pre class="glass-code">${escapeHtml(dialog.payload ?? "")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button>
            <button type="button" class="glass-btn" data-glass-copy-text>${escapeHtml(t("Copy"))}</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "network-services") {
      const rows = (dialog.payload ?? []).map((row) => `
        <tr>
          <td>${escapeHtml(row.display_name ?? row.service_id ?? "unknown")}</td>
          <td>${escapeHtml(String(row.order ?? "—"))}</td>
          <td>${escapeHtml(serviceProxyLabel(row))}</td>
        </tr>`).join("");
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="${escapeHtml(t("Network services"))}">
          <h3>${escapeHtml(t("Network services"))}</h3>
          <p class="glass-dialog-copy">${escapeHtml(t("Read from SystemConfiguration only. The default-route interface, hardware port and BSD device are not reported: the child-process tools that supplied them are gone."))}</p>
          <div class="glass-table-wrap"><table class="glass-table"><thead><tr><th>${escapeHtml(t("Service"))}</th><th>${escapeHtml(t("Order"))}</th><th>${escapeHtml(t("Proxy"))}</th></tr></thead><tbody>${rows || `<tr><td colspan="3">${escapeHtml(t("No services"))}</td></tr>`}</tbody></table></div>
          ${dialog.unavailable?.length ? `<p class="glass-dialog-copy">${escapeHtml(t("Unavailable fields"))}: ${escapeHtml(dialog.unavailable.join(", "))}</p>` : ""}
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button></div>
        </div>
      `);
    } else if (dialog.kind === "dns-query") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="${escapeHtml(t("DNS query"))}">
          <h3>${escapeHtml(t("Resolve through the running engine"))}</h3>
          <label>${escapeHtml(t("Name"))}<input data-glass-dns-name value="${escapeHtml(dialog.payload?.name ?? "www.gstatic.com")}" /></label>
          <label>${escapeHtml(t("Type"))}<input data-glass-dns-type value="${escapeHtml(dialog.payload?.type ?? "A")}" /></label>
          <pre class="glass-code">${escapeHtml(dialog.payload?.result ?? t("Enter a name and Query."))}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button>
            <button type="button" class="glass-btn" data-glass-dns-confirm>${escapeHtml(t("Query"))}</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "credentials") {
      const setup = state.credentialSetup;
      const body = !setup
        ? `<p class="glass-dialog-copy">${escapeHtml(t("Reading credential requirements…"))}</p>`
        : !setup.vaultAvailable
          ? `<p class="glass-dialog-copy">${escapeHtml(t("Credential presence could not be verified, so nothing is being requested and nothing is assumed missing: {error}", { error: setup.error ?? t("The credential vault is unavailable.") }))}</p>`
          : setup.missing.length === 0
            ? `<p class="glass-dialog-copy">${setup.requiredCount === 0
                ? t("This profile references no credentials.")
                : t("All {requiredCount} credential reference(s) are already present in the vault.", { requiredCount: setup.requiredCount })}</p>`
            : `
              <p class="glass-dialog-copy">${escapeHtml(t("{present} of {required} reference(s) are already present. Enter every missing value once; the batch goes straight to the signed native Keychain vault and is never written to the profile, the log, or the configuration digest.", { present: setup.presentCount, required: setup.requiredCount }))}</p>
              ${setup.missing.map((reference, index) => `
                <label>${escapeHtml(credentialLabel(reference.kind))}
                  <input type="password" autocomplete="new-password" data-credential-secret data-credential-index="${index}" aria-label="${escapeHtml(t("Secret for {credential}", { credential: credentialLabel(reference.kind) }))}" />
                </label>
              `).join("")}
            `;
      const canSubmit = Boolean(setup?.vaultAvailable && setup.missing.length && engineIsOff());
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Profile credentials"))}">
          <h3>Credentials${setup?.profileName ? ` · ${escapeHtml(setup.profileName)}` : ""}</h3>
          ${body}
          ${setup?.missing?.length && !engineIsOff() ? `<p class="glass-dialog-copy">${escapeHtml(REASONS.engineNotOff)}</p>` : ""}
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button>
            ${canSubmit ? `<button type="button" class="glass-btn" data-glass-credentials-confirm="${escapeHtml(setup.profileId)}">${escapeHtml(t("Store credentials"))}</button>` : ""}
          </div>
        </div>
      `);
    } else if (dialog.kind === "credential-cleanup") {
      const preview = state.credentialGcPreview;
      const references = (preview?.orphanReferences ?? []).slice(0, 12)
        .map((reference) => `<li>${escapeHtml(credentialLabel(reference.kind))} · ${escapeHtml(reference.id)}</li>`)
        .join("");
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Credential cleanup"))}">
          <h3>${escapeHtml(t("Unused credentials"))}</h3>
          <p class="glass-dialog-copy">${preview
            ? escapeHtml(t("Unused Keychain entries: {count}. Cleanup revalidates the repository snapshot and the vault revision before one atomic deletion.", { count: preview.orphanCount }))
            : t("The credential vault has no unused references.")}</p>
          ${references ? `<ul class="glass-list">${references}</ul>` : ""}
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-credential-gc-cancel>${escapeHtml(t("Close"))}</button>
            ${preview ? `<button type="button" class="glass-btn danger" data-glass-credential-gc-confirm>${escapeHtml(t("Delete unused credentials"))}</button>` : ""}
          </div>
        </div>
      `);
    } else if (dialog.kind === "legacy-profile-migration") {
      const preview = dialog.payload;
      parts.push(`
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
    } else if (dialog.kind === "info") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Info"))}">
          <h3>${escapeHtml(dialog.payload?.title ?? t("Info"))}</h3>
          <p class="glass-dialog-copy">${escapeHtml(dialog.payload?.body ?? "")}</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button></div>
        </div>
      `);
    } else if (dialog.kind === "product-about") {
      const product = state.payload.product;
      const version = product.version ?? "—";
      const status = productAboutStatusText(dialog.payload);
      const update = dialog.payload?.update;
      const phase = dialog.payload?.phase ?? (dialog.payload?.checking ? "checking" : "idle");
      const busy = phase === "checking";
      const canOpen = Boolean(update?.available && update?.version && !busy);
      const notes = update?.notes ? `<p class="product-about-notes">${escapeHtml(String(update.notes).slice(0, 280))}</p>` : "";
      const primaryLabel = phase === "checking"
        ? "Checking…"
        : canOpen
          ? t("Open Download v{value1}", { value1: escapeHtml(String(update.version)) })
          : "";
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog product-about" role="dialog" aria-label="${escapeHtml(t("About Clash for Mac"))}">
          <div class="product-about-icon">${renderCatLogo()}</div>
          <div class="product-about-name">Clash for Mac</div>
          <div class="product-about-sub">${escapeHtml(t("Powered by sing-box"))}</div>
          <div class="product-about-meta">
            <div>版本 ${escapeHtml(String(version))}</div>
            <div>${escapeHtml(String(product.architecture ?? "arm64"))} · macOS ${escapeHtml(String(product.minimum_macos ?? "15.0"))}+</div>
          </div>
          <div class="product-about-status">${escapeHtml(status)}</div>
          ${notes}
          <div class="glass-dialog-actions column">
            ${canOpen ? `<button type="button" class="glass-btn" data-glass-open-update>${primaryLabel}</button>` : ""}
            ${busy && !canOpen ? `<button type="button" class="glass-btn" disabled>${primaryLabel}</button>` : ""}
            <button type="button" class="glass-btn ghost" data-glass-check-update ${busy ? "disabled" : ""}>${phase === "checking" ? "Checking…" : t("Check for Update")}</button>
            <button type="button" class="glass-btn ghost" data-glass-dismiss ${busy ? "disabled" : ""}>${escapeHtml(t("Close"))}</button>
          </div>
          <div class="product-about-copy">© Clash for Mac · ${escapeHtml(String(product.license ?? "GPL-3.0-or-later"))}</div>
        </div>
      `);
    }
  }

  parts.push(runtimeSettingsUI.renderDialog());
  parts.push(automationSettingsUI.renderDialog());
  root.innerHTML = parts.join("");
  runtimeSettingsUI.bindDialog();
  automationSettingsUI.bindDialog();
  positionGlassMenu();
  bindGlassOverlayEvents();
  nativeGeneralSwitches.refresh();
}

function positionGlassMenu() {
  const menu = document.querySelector(".glass-menu");
  if (!menu || !state.profileContextMenu) return;
  const pad = 10;
  const rect = menu.getBoundingClientRect();
  let left = state.profileContextMenu.x;
  let top = state.profileContextMenu.y;
  if (left + rect.width > window.innerWidth - pad) left = Math.max(pad, window.innerWidth - rect.width - pad);
  if (top + rect.height > window.innerHeight - pad) top = Math.max(pad, window.innerHeight - rect.height - pad);
  menu.style.left = `${Math.round(left)}px`;
  menu.style.top = `${Math.round(top)}px`;

  const scroll = menu.querySelector("[data-glass-menu-scroll]");
  const more = menu.querySelector("[data-glass-menu-more]");
  if (scroll && more) {
    const updateMore = () => {
      const overflow = scroll.scrollHeight > scroll.clientHeight + 2;
      const atBottom = scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - 2;
      more.hidden = !overflow || atBottom;
    };
    scroll.addEventListener("scroll", updateMore, { passive: true });
    updateMore();
  }
}

function bindGlassOverlayEvents() {
  document.querySelectorAll("[data-glass-dismiss]").forEach((node) => {
    node.addEventListener("click", () => closeGlassOverlays());
  });

  document.querySelectorAll("[data-profile-menu]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const action = event.currentTarget.dataset.profileMenu;
      const id = event.currentTarget.dataset.profileId;
      state.profileContextMenu = null;
      renderGlassOverlays();
      try {
        await runProfileMenuAction(action, id);
      } catch (error) {
        appendLog("error", "profile", t("{action} failed: {error}", { action: action, error: errorText(error) }));
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-copy-confirm]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const id = event.currentTarget.dataset.glassCopyConfirm;
      const name = document.querySelector("[data-glass-copy-name]")?.value?.trim();
      if (!name) return;
      try {
        const text = await invoke("read_profile_text", { id });
        const result = await invokeProfileChange("import_profile_text", { name, body: text.body });
        await loadProfilesSnapshot();
        closeGlassOverlays();
        appendLog("info", "profile", t("Copied profile to {name}; select it to make it active", { name: result.name }));
      } catch (error) {
        appendLog("error", "profile", t("Copy failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-settings-confirm]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const id = event.currentTarget.dataset.glassSettingsConfirm;
      const name = document.querySelector("[data-glass-settings-name]")?.value?.trim() ?? "";
      const url = document.querySelector("[data-glass-settings-url]")?.value?.trim() ?? "";
      try {
        await invoke("update_profile_info", { id, name, url });
        await loadProfilesSnapshot();
        closeGlassOverlays();
        appendLog("info", "profile", t("Profile settings saved: {name}", { name: name }));
      } catch (error) {
        appendLog("error", "profile", t("Settings failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-delete-confirm]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      const id = event.currentTarget.dataset.glassDeleteConfirm;
      const profile = state.profiles.find((item) => item.id === id);
      try {
        const deleted = await invoke("delete_profile", { id });
        await loadProfilesSnapshot();
        closeGlassOverlays();
        appendLog(
          deleted ? "warning" : "info",
          "profile",
          deleted ? t("Profile deleted: {value1}", { value1: profile?.name ?? id }) : t("Profile already missing: {id}", { id: id }),
        );
      } catch (error) {
        appendLog("error", "profile", t("Delete failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-reset-confirm]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      try {
        const snapshot = await invoke("reset_settings_snapshot");
        applyPersistedSettings(snapshot);
        await loadProfilesSnapshot();
        closeGlassOverlays();
        appendLog("warning", "settings", t("Preferences reset to defaults"));
      } catch (error) {
        appendLog("error", "settings", t("Reset failed: {error}", { error: errorText(error) }));
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-copy-text]").forEach((button) => {
    button.addEventListener("click", async () => {
      const textValue = state.glassDialog?.payload ?? document.querySelector(".glass-code")?.textContent ?? "";
      try {
        await navigator.clipboard.writeText(String(textValue));
        appendLog("info", "clipboard", t("Copied dialog text"));
      } catch (error) {
        appendLog("warning", "clipboard", errorText(error));
      }
    });
  });

  document.querySelectorAll("[data-glass-dns-confirm]").forEach((button) => {
    button.addEventListener("click", async () => {
      const name = document.querySelector("[data-glass-dns-name]")?.value?.trim() ?? "";
      const type = document.querySelector("[data-glass-dns-type]")?.value?.trim() || "A";
      if (!controllerActionAllowed(t("DNS query"), "dns")) {
        state.glassDialog = { kind: "dns-query", payload: { name, type, result: t("Engine is Off; start the engine before querying DNS.") } };
        renderGlassOverlays();
        return;
      }
      const token = captureEngineIdentityToken();
      try {
        const result = await invoke("dns_query", { name, record_type: type, recordType: type });
        if (!engineIdentityTokenIsCurrent(token)) return;
        state.glassDialog = { kind: "dns-query", payload: { name, type, result: JSON.stringify(result, null, 2) } };
        renderGlassOverlays();
      } catch (error) {
        if (!engineIdentityTokenIsCurrent(token)) return;
        const message = errorText(error);
        appendLog("error", "dns", t("DNS query failed: {message}", { message: message }));
        state.glassDialog = { kind: "dns-query", payload: { name, type, result: message } };
        renderGlassOverlays();
      }
    });
  });

  document.querySelectorAll("[data-glass-open-rules]").forEach((button) => {
    button.addEventListener("click", async () => {
      closeGlassOverlays();
      state.activePage = "rules";
      await loadRulesSnapshot();
      renderPage();
    });
  });

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
          t("{name} {value2}, credentials verified, and selected", { name: outcome.name, value2: outcome.reused ? "recovered" : "imported" }),
        );
        state.legacyProfileMigrationPreview = null;
        closeGlassOverlays();
      } catch (error) {
        const message = errorText(error);
        appendLog(
          "error",
          "migration",
          `${committed ? "Migrated profile staging failed" : t("Legacy profile migration failed")}: ${message}`,
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

  document.querySelectorAll("[data-glass-credentials-confirm]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const profileId = event.currentTarget.dataset.glassCredentialsConfirm;
      const setup = state.credentialSetup;
      if (!setup || setup.profileId !== profileId) return;
      const inputs = [...document.querySelectorAll("[data-credential-secret]")];
      const secrets = setup.missing.map((_reference, index) => inputs
        .find((input) => Number(input.dataset.credentialIndex) === index)?.value ?? "");
      let batch = [];
      try {
        batch = credentialProvisionBatch(setup.missing, secrets);
        const receipt = await invoke("provision_profile_credentials", {
          profileId,
          credentials: batch,
        });
        normalizeCredentialReceipt(receipt, profileId);
        appendLog("info", "credentials", t("Stored {count} credential reference(s) for {profileName}", { count: batch.length, profileName: setup.profileName }));
        closeGlassOverlays();
        state.credentialSetup = null;
      } catch (error) {
        appendLog("error", "credentials", errorText(error));
      } finally {
        // The secrets leave this renderer as soon as the vault has them.
        for (const entry of batch) entry.secret = "";
        for (const input of inputs) input.value = "";
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-credential-gc-confirm]").forEach((button) => {
    button.addEventListener("click", async () => {
      const preview = state.credentialGcPreview;
      if (!preview) return;
      try {
        const receipt = await invoke("commit_credential_gc", { previewId: preview.previewId });
        normalizeGcReceipt(receipt, preview.orphanCount);
        appendLog("info", "credentials", t("Removed {removed_count} unused credential reference(s)", { removed_count: receipt.removed_count }));
      } catch (error) {
        appendLog("error", "credentials", errorText(error));
      } finally {
        // A preview is one-shot on the server: any rejection needs a new one.
        state.credentialGcPreview = null;
        closeGlassOverlays();
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-credential-gc-cancel]").forEach((button) => {
    button.addEventListener("click", async () => {
      const preview = state.credentialGcPreview;
      state.credentialGcPreview = null;
      closeGlassOverlays();
      if (preview) {
        try {
          await invoke("cancel_credential_gc", { previewId: preview.previewId });
        } catch (error) {
          appendLog("error", "credentials", errorText(error));
        }
      }
      renderPage();
    });
  });

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

async function runProfileMenuAction(action, id) {
  const profile = state.profiles.find((item) => item.id === id);
  if (!profile) throw new Error(t("profile not found: {id}", { id: id }));

  switch (action) {
    case "select":
      await selectProfileById(id);
      return;
    case "edit":
      await openProfileInspector(id, "edit");
      appendLog("info", "profile", t("edit editor opened for {name}", { name: profile.name }));
      return;
    case "outbounds":
      await openProfileInspector(id, "edit", "outbounds");
      appendLog("info", "profile", t("outbounds section editor opened for {name}", { name: profile.name }));
      return;
    case "route":
      await openProfileInspector(id, "edit", "route");
      appendLog("info", "profile", t("route section editor opened for {name}", { name: profile.name }));
      return;
    case "edit-external":
      await invoke("open_profile_externally", { id });
      appendLog("info", "profile", t("Opened {name} externally", { name: profile.name }));
      return;
    case "update": {
      const result = await invokeProfileChange("update_profile", { id });
      await loadProfilesSnapshot();
      appendLog("info", "profile", t("{name} subscription updated", { name: result.name }));
      if (result.credential_cleanup_pending) {
        appendLog(
          "warning",
          "profile",
          t("{name} updated. Old credentials are retained for recovery.{value2}", { name: result.name, value2: result.credential_cleanup_error ? t(" Cleanup: {error}", { error: result.credential_cleanup_error }) : "" }),
        );
      }
      return;
    }
    case "reveal":
      await invoke("reveal_profile", { id });
      appendLog("info", "profile", t("Show in folder: {name}", { name: profile.name }));
      return;
    case "copy":
      state.glassDialog = { kind: "copy", id };
      renderGlassOverlays();
      return;
    case "qrcode":
      await openProfileInspector(id, "qrcode");
      appendLog("info", "profile", t("QRCode opened for {name}", { name: profile.name }));
      return;
    case "credentials":
      await openCredentialSetup(id);
      return;
    case "settings":
      state.glassDialog = { kind: "settings", id };
      renderGlassOverlays();
      return;
    case "delete":
      // WKWebView often swallows window.confirm (always false) — use in-app glass dialog.
      state.glassDialog = { kind: "delete", id };
      renderGlassOverlays();
      return;
    default:
      throw new Error(t("unknown profile menu action: {action}", { action: action }));
  }
}

/// Asks the vault which of a profile's immutable credential references are still
/// missing, then opens the entry dialog. Nothing is assumed present or missing
/// when the vault cannot answer.
async function openCredentialSetup(id) {
  const profile = state.profiles.find((item) => item.id === id);
  if (!profile) throw new Error(t("profile not found: {id}", { id: id }));
  state.credentialSetup = null;
  state.glassDialog = { kind: "credentials", id };
  renderGlassOverlays();
  try {
    const requirements = normalizeCredentialReferences(
      await invoke("profile_credential_requirements", { id }),
    );
    let missing = [];
    let presentCount = 0;
    if (requirements.length) {
      const presence = normalizeCredentialPresence(
        await invoke("profile_credential_presence", { id }),
        requirements,
      );
      missing = presence.filter(({ present }) => !present).map(({ reference }) => reference);
      presentCount = requirements.length - missing.length;
    }
    state.credentialSetup = {
      profileId: id,
      profileName: profile.name,
      requiredCount: requirements.length,
      presentCount,
      missing,
      vaultAvailable: true,
      error: null,
    };
  } catch (error) {
    const message = errorText(error);
    state.credentialSetup = {
      profileId: id,
      profileName: profile.name,
      requiredCount: null,
      presentCount: null,
      missing: [],
      vaultAvailable: false,
      error: message,
    };
    appendLog("error", "credentials", t("Could not verify credentials for {name}: {message}", { name: profile.name, message: message }));
  }
  if (state.glassDialog?.kind === "credentials") renderGlassOverlays();
}

function renderProfiles() {
  const repositoryReason = state.profilesUnavailableReason
    ? t("Profile repository unavailable: {profilesUnavailableReason}", { profilesUnavailableReason: state.profilesUnavailableReason })
    : null;
  const mutationReason = repositoryReason;
  const blocked = mutationReason ? `disabled title="${escapeHtml(mutationReason)}"` : "";
  return `
    <div class="profiles-layout">
      <section class="cfw-profile-remote">
        <div class="cfw-url-box">
          <input data-profile-url placeholder="${escapeHtml(t("HTTPS subscription or node link"))}" aria-label="${escapeHtml(t("Subscription URL or node link"))}" ${blocked} />
          <button class="paste-icon" data-action="paste-profile-url" title="${escapeHtml(t("Paste URL"))}" ${blocked}>▣</button>
        </div>
        <button class="cfw-big-button" data-action="import-profile" ${blocked}>${escapeHtml(t("Import Link"))}</button>
        <button class="cfw-big-button" data-action="update-all-profiles" ${blocked}>${escapeHtml(t("Update All"))}</button>
        <button class="cfw-big-button" data-action="import-profile-file" ${blocked}>${escapeHtml(t("Import File"))}</button>
        <input class="profile-file-hidden" data-profile-file type="file" accept="${PROFILE_SOURCE_ACCEPT}" aria-label="${escapeHtml(t("Local JSON, YAML, WireGuard, or node-link profile"))}" ${blocked} />
      </section>

      <p class="profile-note">${escapeHtml(t("Clash YAML imports nodes, groups, supported routing rules, DNS, and hosts. Unsupported policies are reported before saving."))}</p>
      ${mutationReason ? `<p class="profile-note">${escapeHtml(mutationReason)}</p>` : ""}

      <section class="cfw-profile-list">
        ${repositoryReason ? `
          <div class="empty-profile-state" role="alert">
            <p>${escapeHtml(repositoryReason)}</p>
            <button data-action="reload-dashboard">${escapeHtml(t("Reload profile repository"))}</button>
          </div>
        ` : state.profiles.length ? state.profiles.map((profile) => `
          <article class="cfw-profile-card ${profile.active ? "active" : ""}" data-profile-card="${escapeHtml(profile.id)}" ${profile.active ? 'aria-current="true"' : ""}>
            <i></i>
            <div class="profile-card-main">
              <h3>${escapeHtml(profile.name)}</h3>
              <p title="${escapeHtml(t("Time since this profile was saved in Clash for Mac"))}">${escapeHtml(profileSourceLabel(profile))} (${escapeHtml(profile.updated)})</p>
            </div>
            <div class="profile-card-primary">
              <button data-profile-action="edit" data-profile-id="${escapeHtml(profile.id)}" title="${escapeHtml(t("Open this profile"))}">‹›</button>
            </div>
          </article>
        `).join("") : `
          <div class="empty-profile-state">
            <p>${escapeHtml(t("No profiles found in the managed profiles directory."))}</p>
            <button data-action="migrate-legacy-profiles">${escapeHtml(t("Migrate selected legacy subscription"))}</button>
          </div>
        `}
      </section>
      ${renderProfileInspector()}
    </div>
  `;
}

function profileSourceLabel(profile) {
  switch (profile.sourceKind) {
    case "local": return t("local file");
    case "subscription": return "subscription";
    default: throw new TypeError("profile snapshot has an invalid source kind");
  }
}

function renderProfileInspector() {
  const inspector = state.profileInspector;
  if (!inspector) return "";
  const profile = inspector.profile ?? {};
  const title = `${profile.name ?? inspector.id} · ${inspector.mode}`;
  const sourceUrl = profile.source_url ?? profile.sourceUrl ?? null;
  let body = "";
  if (inspector.mode === "edit") {
    body = `
      <dl class="detail-grid">
        <div><dt>${escapeHtml(t("Source URL"))}</dt><dd>${escapeHtml(sourceUrl ?? t("local file"))}</dd></div>
        <div><dt>${escapeHtml(t("Size"))}</dt><dd>${escapeHtml(formatBytes(profile.bytes ?? 0))}</dd></div>
        <div><dt>${escapeHtml(t("Active"))}</dt><dd>${profile.active ? "yes" : "no"}</dd></div>
      </dl>
      <textarea class="profile-editor" data-profile-editor spellcheck="false">${escapeHtml(profile.body ?? "")}</textarea>
      <div class="row-actions">
        <button class="button" data-action="save-profile-editor">${escapeHtml(t("Save JSON"))}</button>
        ${sourceUrl ? `<button class="button ghost" data-action="update-profile-from-inspector">${escapeHtml(t("Update from subscription"))}</button>` : ""}
        <button class="button ghost" data-action="close-profile-inspector">${escapeHtml(t("Close"))}</button>
      </div>
      <p class="muted">${escapeHtml(t("Changes are validated before switching the running core. Existing connections may reconnect."))}</p>
    `;
  } else if (inspector.mode === "qrcode") {
    body = inspector.svg
      ? `<div class="profile-qr">${inspector.svg}</div><p class="muted">${escapeHtml(sourceUrl ?? "")}</p>`
      : `<p class="empty">${escapeHtml(inspector.error ?? t("This local profile has no subscription URL."))}</p>`;
  } else {
    body = `
      <dl class="detail-grid">
        <div><dt>${escapeHtml(t("ID"))}</dt><dd>${escapeHtml(profile.id ?? inspector.id)}</dd></div>
        <div><dt>${escapeHtml(t("Active"))}</dt><dd>${profile.active ? "yes" : "no"}</dd></div>
        <div><dt>${escapeHtml(t("Source URL"))}</dt><dd>${escapeHtml(sourceUrl ?? t("local file"))}</dd></div>
      </dl>
    `;
  }

  return `
    <section class="panel profile-inspector">
      <div class="section-heading">
        <div>
          <p class="label">${escapeHtml(t("Profile Inspector"))}</p>
          <h3>${escapeHtml(title)}</h3>
        </div>
        <button class="button ghost" data-action="close-profile-inspector">${escapeHtml(t("Close"))}</button>
      </div>
      ${body}
    </section>
  `;
}


function renderLogs() {
  const logs = visibleLogs();
  return `
    <div class="logs-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">${escapeHtml(t("Diagnostics"))}</p>
          <h3>${logCountLabel(logs.length)}</h3>
        </div>
        <div class="search-box">
          <input value="${escapeHtml(state.logSearch)}" data-log-search aria-label="${escapeHtml(t("Search logs"))}" placeholder="${escapeHtml(t("Search logs or regex"))}" />
        </div>
        <div class="segmented" data-log-filters>
          ${["all", "info", "debug", "warning", "error"].map((level) => `
            <button type="button" class="${state.logFilter === level ? "selected" : ""}" data-log-filter="${level}">${level.toUpperCase()}</button>
          `).join("")}
        </div>
        <div class="toolbar-actions">
          <button type="button" class="button ghost" data-action="toggle-log-stream">${state.logsPaused ? t("Start") : t("Stop")}</button>
          <button type="button" class="button ghost" data-action="copy-logs">${escapeHtml(t("Copy"))}</button>
          <button type="button" class="button ghost" data-action="reveal-logs">${escapeHtml(t("Open Folder"))}</button>
          <button type="button" class="button ghost" data-action="clear-logs">${escapeHtml(t("Clear"))}</button>
        </div>
      </section>

      <section class="panel log-stream">
        ${renderLogStreamHtml()}
      </section>
    </div>
  `;
}

function renderFeedback() {
  const product = state.payload.product;
  const version = product.version ?? "—";
  const update = state.updateInfo;
  const updateLine = update?.available && update?.version
    ? t("New version available: v{value1} (current v{value2}).", { value1: escapeHtml(String(update.version)), value2: escapeHtml(String(update.current ?? version)) })
    : t("Current build v{value1} — the menu bar Clash for Mac → Check for Update… also works.", { value1: escapeHtml(String(version)) });
  const platform = state.platform;
  return `
    <div class="feedback-layout">
      <section class="panel hero-panel">
        <div>
          <p class="label">${escapeHtml(t("About"))}</p>
          <h3>${escapeHtml(product.name ?? "Clash for Mac")} v${escapeHtml(String(version))}${update?.available && update?.version ? ` → v${escapeHtml(String(update.version))}` : ""}</h3>
          <p class="muted">${escapeHtml(product.license ?? "GPL-3.0-or-later")} · ${escapeHtml(product.architecture ?? "arm64")} · macOS ${escapeHtml(product.minimum_macos ?? "15.0")} or later</p>
        </div>
        <span class="badge">${escapeHtml(t("ARM64 macOS only"))}</span>
      </section>

      <section class="panel">
        <p class="label">${escapeHtml(t("Updates"))}</p>
        <h3>${escapeHtml(t("Check for Updates"))}</h3>
        <p class="muted">${updateLine}</p>
        <div class="toolbar-actions">
          <button class="button" data-action="check-for-updates">${escapeHtml(t("Check for Updates"))}</button>
        </div>
      </section>

      <section class="panel">
        <p class="label">${escapeHtml(t("Architecture"))}</p>
        <h3>${escapeHtml(t("How this build runs the network"))}</h3>
        ${platform ? `
          <dl class="ports-list feedback-list">
            <div><dt>${escapeHtml(t("system proxy"))}</dt><dd>${escapeHtml(platform.system_proxy_strategy ?? "")}</dd></div>
            <div><dt>tunnel</dt><dd>${escapeHtml(platform.tun_strategy ?? "")}</dd></div>
            <div><dt>helper</dt><dd>${escapeHtml(platform.helper_strategy ?? "")}</dd></div>
            <div><dt>launchd</dt><dd>${escapeHtml(platform.launchd_strategy ?? "")}</dd></div>
          </dl>
        ` : `<p class="muted">${escapeHtml(t("Platform design is unavailable."))}</p>`}
      </section>

      <section class="panel">
        <p class="label">${escapeHtml(t("Dashboard"))}</p>
        <h3>${escapeHtml(t("Layout reference"))}</h3>
        <dl class="ports-list feedback-list">
          <div><dt>window</dt><dd>${escapeHtml(t("850 x 603 minimum baseline"))}</dd></div>
          <div><dt>pages</dt><dd>${escapeHtml(PAGES.map((page) => page.id).join(" / "))}</dd></div>
        </dl>
      </section>
    </div>
  `;
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

const declaredPageIds = PAGES.map(({ id }) => id).sort();
const rendererPageIds = Object.keys(pageRenderers).sort();
if (
  declaredPageIds.length !== rendererPageIds.length
  || declaredPageIds.some((id, index) => id !== rendererPageIds[index])
) {
  throw new TypeError("renderer page implementations must exactly match the shared page contract");
}

function renderPage() {
  editingRender.render([
    state.activePage, state.glassDialog, state.runtimeSettingsDialog,
    state.automationDialog, state.profileInspector,
  ], renderPageContent);
}

function renderPageContent() {
  nativeGeneralSwitches.beforeRender();
  const page = pageById(state.activePage);
  const renderer = pageRenderers[page.id];
  if (typeof renderer !== "function") {
    throw new TypeError(`renderer is unavailable for page ${page.id}`);
  }
  document.title = "";
  const productName = document.getElementById("product-name");
  if (productName) productName.textContent = state.payload.product?.name ?? "Clash for Mac";
  const statusTitle = document.getElementById("status-title");
  if (statusTitle) statusTitle.textContent = state.mode ? t("{title} - {mode} Mode", { title: t(page.title), mode: t(state.mode) }) : t(page.title);
  document.getElementById("page-title").textContent = t(page.title);
  document.getElementById("page-summary").textContent = t(page.summary);
  const running = state.engine.active;
  const sidebarStatus = document.getElementById("sidebar-status");
  if (sidebarStatus) sidebarStatus.textContent = running ? t("Connected") : t("Disconnected");
  const sidebarDot = document.getElementById("sidebar-status-dot");
  if (sidebarDot) sidebarDot.className = running ? "on" : "";
  updateStatusBar();

  renderNav();
  document.getElementById("page").innerHTML = renderer();
  bindPageEvents();
  renderGlassOverlays();
  nativeGeneralSwitches.refresh();
  if (state.profileInspector?.mode === "edit" && state.profileInspector.focusKey) {
    requestAnimationFrame(() => focusProfileEditorSection(state.profileInspector.focusKey));
  }
}

function updateStatusBar() {
  const up = document.getElementById("upload-rate");
  const down = document.getElementById("download-rate");
  const runtime = document.getElementById("runtime-value");
  const progress = document.getElementById("traffic-progress");
  if (up) up.textContent = formatRate(state.traffic.upload);
  if (down) down.textContent = formatRate(state.traffic.download);
  if (runtime) runtime.textContent = formatRuntime(state.traffic.runtimeSeconds);
  if (progress) {
    const total = Math.min(100, Math.max(0, (state.traffic.upload + state.traffic.download) * 4));
    progress.style.width = `${total}%`;
  }
}

function scheduleRender() {
  if (runtime.renderFrame !== null) return;
  runtime.renderFrame = window.requestAnimationFrame(() => {
    runtime.renderFrame = null;
    runtime.connectionRowEls = null;
    renderPage();
  });
}

/// Pushes a proxy mode to the running engine. It is the only runtime switch the
/// clash-compatible controller accepts, and it is not a persisted preference, so
/// nothing is written to the preference store here.
async function applyProxyMode(mode) {
  if (!["Global", "Rule", "Direct"].includes(mode)) throw new TypeError("Proxy mode is invalid");
  if (!controllerActionAllowed(t("Proxy mode {mode}", { mode: t(mode) }), "mode")) return;
  if (!freshProxyControllerSnapshotAvailable()) {
    appendLog("info", "mode", t("Proxy mode {mode} requires a fresh controller snapshot", { mode: t(mode) }));
    return false;
  }
  const invokeMutation = () => invoke("set_proxy_mode", { mode });
  return enqueueControllerMutation({
    lane: "proxy-mode",
    kind: "mode",
    target: mode,
    source: "mode",
    failureLabel: t("Proxy mode {mode} was not applied", { mode: t(mode) }),
    successMessage: t("Proxy mode switched to {mode}", { mode: t(mode) }),
    breakConnectionsReason: "mode",
    invokeMutation,
    readObserved: controllerModeFromSnapshot,
    publishObserved: (observed) => { state.mode = observed; },
  });
}

async function applyProxySelection(groupName, proxyName) {
  if (engineIsOff() && state.savedProfilePolicy) {
    const policy = state.savedProfilePolicy;
    const group = policy.groups.find((item) => item.name === groupName);
    if (state.savedProxySelectionBusy || !group || !isManualProxyGroup(group.type)
      || !group.options.some((item) => item.name === proxyName)) return false;
    state.savedProxySelectionBusy = true;
    try {
      await invoke("select_proxy", { profileId: policy.profileId, group: groupName, proxy: proxyName });
      await loadProfilesSnapshot();
      const observed = state.savedProfilePolicy;
      if (observed?.profileId !== policy.profileId || observed.groups.find((item) => item.name === groupName)?.now !== proxyName) {
        throw new Error("Saved proxy selection could not be confirmed");
      }
      appendLog("info", "proxy", t("Saved {proxyName} for {groupName}; it will apply on the next start", { proxyName: proxyName, groupName: groupName }));
      return true;
    } catch (error) {
      appendLog("error", "proxy", errorText(error));
      return false;
    } finally {
      state.savedProxySelectionBusy = false;
      renderPage();
    }
  }
  const group = state.proxyGroups.find((item) => item.name === groupName);
  if (!group) return false;
  if (!freshProxyControllerSnapshotAvailable()) {
    if (!state.engine.active) {
      controllerActionAllowed(t("Selecting proxy in {groupName}", { groupName: groupName }), "proxy");
    } else {
      appendLog("info", "proxy", t("Proxy selection requires a fresh controller snapshot"));
    }
    return false;
  }
  if (!isManualProxyGroup(group.type)) {
    appendLog("error", "proxy", t("The current proxy group is selected by the engine and is read-only"));
    return false;
  }
  if (!group.options.some((item) => item.name === proxyName)) {
    appendLog("error", "proxy", t("Proxy selection is not an option in the current controller snapshot"));
    return false;
  }
  if (!controllerActionAllowed(t("Selecting proxy in {groupName}", { groupName: groupName }), "proxy")) return false;
  const invokeMutation = () => invoke("select_proxy", { group: groupName, proxy: proxyName });
  return enqueueControllerMutation({
    lane: `proxy-selector:${groupName}`,
    kind: "selector",
    groupName,
    target: proxyName,
    source: "proxy",
    failureLabel: t("Proxy selection {groupName} → {proxyName} was not applied", { groupName: groupName, proxyName: proxyName }),
    successMessage: t("Proxy group {groupName} switched to {proxyName}", { groupName: groupName, proxyName: proxyName }),
    breakConnectionsReason: groupName,
    invokeMutation,
    readObserved: (snapshot) => controllerSelectorFromSnapshot(snapshot, groupName),
    publishObserved: (observed) => {
      const current = state.proxyGroups.find((item) => item.name === groupName);
      if (current && observed !== null) current.now = observed;
    },
  });
}

/// Applies the selected profile.
///
/// With the engine running this restarts it onto a freshly projected
/// configuration; with the engine Off the projection is validated and staged,
/// which the log line states rather than implying a configuration was pushed.
async function applyActiveProfile(context) {
  const applied = await invoke("apply_active_profile");
  appendLog(
    "info",
    "profile",
    t("{name}: projection {value2} ({value3}){value4}", { name: applied.name, value2: applied.applied ? t("applied and engine restarted") : t("validated and staged (engine is off)"), value3: formatBytes(applied.bytes ?? 0), value4: context ? t(" after {context}", { context }) : "" }),
  );
  await loadRuntimeProjection();
  return applied;
}

async function invokeProfileChange(command, args) {
  try {
    const result = await invoke(command, args);
    if (result?.reset_proxy_groups?.length) {
      appendLog("warning", "profile", t("Saved nodes were removed from these groups; the new defaults apply: {value1}", { value1: result.reset_proxy_groups.join(", ") }));
    }
    return result;
  } finally {
    await loadProfilesSnapshot();
    await loadEngineStatus();
    if (state.engine.active) await loadControllerSnapshot();
    await loadRuntimeProjection();
  }
}

async function selectProfileById(id) {
  const profile = state.profiles.find((item) => item.id === id);
  if (!profile) throw new Error(t("profile not found: {id}", { id: id }));
  if (profile.active) {
    appendLog("info", "profile", t("{name} is already active", { name: profile.name }));
    return false;
  }
  await invokeProfileChange("select_profile", { id });
  appendLog("info", "profile", t("{name} selected", { name: profile.name }));
  return true;
}

function bindPageEvents() {
  document.querySelectorAll("[data-toggle]").forEach((input) => {
    input.addEventListener("change", async (event) => {
      const key = event.currentTarget.dataset.toggle;
      const checked = event.currentTarget.checked;
      await applyUiToggle(key, checked);
    });
  });

  document.querySelectorAll("[data-theme-setting], [data-font-family], [data-language-setting]").forEach((input) => {
    input.addEventListener("change", async () => {
      if (state.settingsUnavailableReason) {
        appendLog("warning", "settings", state.settingsUnavailableReason);
        renderPage();
        return;
      }
      try {
        const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
        applyPersistedSettings(snapshot);
        appendLog("info", "settings", t("Appearance saved"));
      } catch (error) {
        appendLog("error", "settings", t("Appearance refused: {error}", { error: errorText(error) }));
        try {
          await loadSettingsSnapshot();
        } catch (refreshError) {
          resetPersistedSettingsToSafeState();
          state.settingsUnavailableReason = t("Preferences are unavailable because the native settings snapshot could not be verified. Reload from disk before changing them.");
          appendLog("error", "settings", t("Appearance recovery failed: {error}", { error: errorText(refreshError) }));
        }
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-rule-page]").forEach((button) => button.addEventListener("click", () => { changeRulePage(Number(button.dataset.rulePage)); renderPage(); }));
  document.querySelectorAll("[data-proxy-page]").forEach((button) => button.addEventListener("click", () => {
    changeProxyPage(Number(button.dataset.proxyPage));
    renderPage();
  }));
  const proxyFilter = document.querySelector("[data-proxy-filter]");
  if (proxyFilter) {
    proxyFilter.addEventListener("input", (event) => {
      state.proxyFilter = event.currentTarget.value;
      renderPage();
    });
  }

  document.querySelectorAll("[data-collapse-group]").forEach((button) => {
    button.addEventListener("click", (event) => {
      const group = event.currentTarget.dataset.collapseGroup;
      if (state.collapsedProxyGroups.has(group)) {
        state.collapsedProxyGroups.delete(group);
      } else {
        state.collapsedProxyGroups.add(group);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-scroll-group]").forEach((button) => {
    button.addEventListener("click", (event) => {
      const group = event.currentTarget.dataset.scrollGroup;
      document.getElementById(`proxy-group-${slugDomId(group)}`)?.scrollIntoView({ block: "start", behavior: "smooth" });
    });
  });

  document.querySelectorAll("[data-proxy-group-tab]").forEach((button) => {
    button.addEventListener("click", (event) => {
      cancelDelayTest();
      state.activeProxyGroup = event.currentTarget.dataset.proxyGroupTab;
      renderPage();
    });
  });

  const profileFile = document.querySelector("[data-profile-file]");
  if (profileFile) {
    profileFile.addEventListener("change", () => {
      handleAction("import-profile-file").catch((error) => {
        appendLog("error", "profile", errorText(error));
        renderPage();
      });
    });
  }

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

  document.querySelectorAll("[data-mode]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      await applyProxyMode(event.currentTarget.dataset.mode);
      renderPage();
    });
  });

  document.querySelectorAll("[data-group][data-node]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      await applyProxySelection(
        event.currentTarget.dataset.group,
        event.currentTarget.dataset.node,
      );
      renderPage();
    });
  });

  document.querySelectorAll("[data-profile-card]").forEach((card) => {
    card.addEventListener("click", async (event) => {
      // CFW: clicking the card selects it. Ignore clicks on action buttons/icons.
      if (event.target.closest("button, a, input, textarea, select")) return;
      const id = card.dataset.profileCard;
      if (!id) return;
      try {
        await selectProfileById(id);
      } catch (_error) {
        // selectProfileById already logged
      }
      renderPage();
    });
    card.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      event.stopPropagation();
      openProfileContextMenu(card.dataset.profileCard, event.clientX, event.clientY);
    });
  });

  document.querySelectorAll("[data-profile-action]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const action = event.currentTarget.dataset.profileAction;
      const id = event.currentTarget.dataset.profileId;
      try {
        await openProfileInspector(id, action);
        appendLog("info", "profile", t("{action} opened for {id}", { action: action, id: id }));
      } catch (error) {
        appendLog("error", "profile", t("{action} failed for {id}: {error}", { action: action, id: id, error: errorText(error) }));
      }
      renderPage();
    });
  });

  bindProviderButtons();
  runtimeSettingsUI.bindPage();

  const logSearch = document.querySelector("[data-log-search]");
  if (logSearch) {
    logSearch.addEventListener("input", (event) => {
      state.logSearch = event.currentTarget.value;
      patchLogStream();
    });
  }

  bindConnectionRowEvents(document);

  const connectionSearch = document.querySelector("[data-connection-search]");
  if (connectionSearch) {
    connectionSearch.addEventListener("input", (event) => {
      state.connectionSearch = event.currentTarget.value;
      renderPage();
    });
  }

  const ruleSearch = document.querySelector("[data-rule-search]");
  if (ruleSearch) {
    ruleSearch.addEventListener("input", (event) => {
      state.ruleSearch = event.currentTarget.value;
      renderPage();
    });
  }

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

  document.querySelectorAll("[data-connection-sort]").forEach((button) => {
    button.addEventListener("click", (event) => {
      const sort = event.currentTarget.dataset.connectionSort;
      if (state.connectionSort === sort) {
        state.connectionSortDesc = !state.connectionSortDesc;
      } else {
        state.connectionSort = sort;
        state.connectionSortDesc = false;
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-modal-stop]").forEach((modal) => {
    modal.addEventListener("click", (event) => event.stopPropagation());
  });

  document.querySelectorAll("[data-copy-text]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const value = event.currentTarget.dataset.copyText ?? "";
      try {
        await navigator.clipboard.writeText(value);
        appendLog("info", "clipboard", t("Connection field copied"));
      } catch (_error) {
        appendLog("warning", "clipboard", t("Clipboard API refused copy"));
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-connection-facet]").forEach((button) => {
    button.addEventListener("click", (event) => {
      state.connectionSearch = event.currentTarget.dataset.connectionFacet;
      renderPage();
    });
  });


}

function bindGlobalEvents() {
  if (runtime.globalEventsBound) return;
  runtime.globalEventsBound = true;
  editingRender.bind();

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && (state.profileContextMenu || state.glassDialog || state.runtimeSettingsDialog || state.automationDialog)) {
      event.preventDefault();
      closeGlassOverlays();
    }
  });

  document.addEventListener("click", (event) => {
    const eventTarget = event.target instanceof Element ? event.target : event.target?.parentElement;
    const filter = eventTarget?.closest("[data-log-filter]");
    if (filter) {
      event.preventDefault();
      const next = filter.dataset.logFilter || "all";
      if (state.logFilter === next) return;
      state.logFilter = next;
      document.querySelectorAll("[data-log-filter]").forEach((button) => {
        button.classList.toggle("selected", button.dataset.logFilter === state.logFilter);
      });
      patchLogStream();
      return;
    }
    const target = eventTarget?.closest("[data-action]");
    if (!target) return;
    event.preventDefault();
    event.stopPropagation();
    handleAction(target.dataset.action).catch((error) => {
      appendLog("error", "ui", errorText(error));
      renderPage();
    });
  });

  document.addEventListener("keydown", (event) => {
    const key = event.key.toLowerCase();
    const usesCommand = event.metaKey || event.ctrlKey;
    if (!usesCommand || event.altKey) return;

    const target = event.target;
    const isEditable = target instanceof HTMLInputElement
      || target instanceof HTMLTextAreaElement
      || target instanceof HTMLSelectElement
      || target?.isContentEditable;
    const pageShortcuts = {
      "1": "general",
      "2": "proxies",
      "3": "profiles",
      "4": "logs",
      "5": "connections",
      "6": "settings",
    };
    if (!isEditable && pageShortcuts[key]) {
      event.preventDefault();
      state.activePage = pageShortcuts[key];
      appendLog("info", "shortcut", t("Opened {value1}", { value1: pageById(state.activePage).title }));
      renderPage();
      return;
    }
    if (isEditable) return;

    const shortcutAction = {
      g: () => applyProxyMode("Global"),
      r: () => applyProxyMode("Rule"),
      d: () => applyProxyMode("Direct"),
      p: () => applyToggle("systemProxy", !modeHasSystemProxy(state.engine.desiredMode), "shortcut"),
      t: () => applyToggle("tunMode", !modeHasTunnel(state.engine.desiredMode), "shortcut"),
      s: () => handleAction("save-settings"),
    }[key];
    if (shortcutAction) {
      event.preventDefault();
      shortcutAction().catch((error) => {
        appendLog("error", "shortcut", errorText(error));
        renderPage();
      });
    }
  });
}

/// Session-only view options. The 0.4.0 preference store has no field for them,
/// so they change what this window shows and are never written to disk.
const SESSION_TOGGLES = new Set(["breakOnProxyChange", "hideUnavailable", "showProcess"]);
const PERSISTED_TOGGLES = new Set([
  "startAtLogin",
  "silentStart",
  "checkForUpdates",
  "retainWindowBounds",
]);

async function applyUiToggle(key, checked) {
  try {
    await applyToggle(key, checked, "ui");
  } catch (error) {
    appendLog("error", "ui", t("{key} refused: {error}", { key, error: errorText(error) }));
  }
  renderPage();
}

async function applyToggle(key, checked, source) {
  if (key === "allowLan") return runtimeSettingsUI.toggleLAN(checked);
  if (key === "ipv6DNS") return runtimeSettingsUI.toggleIPv6DNS(checked);
  const isEngineMutation = key === "coreRunning" || key === "systemProxy" || key === "tunMode";
  if (PERSISTED_TOGGLES.has(key) && state.settingsUnavailableReason) {
    throw new Error(state.settingsUnavailableReason);
  }
  if (isEngineMutation && !engineToggleChangeAllowed(key, checked, source)) {
    renderPage();
    return false;
  }
  if (isEngineMutation && state.engineMutationBusy) {
    throw new Error("A network mode change is already in progress");
  }
  const previous = state.toggles[key];
  if (!isEngineMutation) state.toggles[key] = checked;
  const engineRequestId = isEngineMutation ? runtime.engineStatusRequestId + 1 : null;
  if (isEngineMutation) {
    runtime.engineStatusRequestId = engineRequestId;
    state.engineMutationBusy = true;
    state.engineMutationError = null;
    renderPage();
  }
  try {
    if (key === "coreRunning") {
      const status = await invoke("set_core_enabled", { enabled: checked });
      if (engineRequestId === runtime.engineStatusRequestId) applyEngineStatus(status);
      else await loadEngineStatus();
      await loadRuntimeProjection();
      if (state.engine.active) await loadControllerSnapshotWithRetry(6, 500);
    } else if (key === "systemProxy") {
      const status = await invoke("set_system_proxy_enabled", { enabled: checked });
      if (engineRequestId === runtime.engineStatusRequestId) applyEngineStatus(status);
      else await loadEngineStatus();
      await loadNetworkDiagnostics();
      await loadRuntimeProjection();
      if (state.engine.active) await loadControllerSnapshotWithRetry(6, 500);
    } else if (key === "tunMode") {
      const status = await invoke("set_tun_enabled", { enabled: checked });
      if (engineRequestId === runtime.engineStatusRequestId) applyEngineStatus(status);
      else await loadEngineStatus();
      await loadRuntimeProjection();
      if (state.engine.active) await loadControllerSnapshotWithRetry(12, 500);
    } else if (key === "startAtLogin") {
      const snapshot = await invoke("set_launch_at_login_enabled", { enabled: checked });
      applyPersistedSettings(snapshot);
    } else if (SESSION_TOGGLES.has(key)) {
      appendLog("info", source, t("{key} changed to {value2} for this session", { key: key, value2: checked ? "on" : "off" }));
      return;
    } else {
      const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
      applyPersistedSettings(snapshot);
    }
    appendLog("info", source, isEngineMutation
      ? t("{key} request completed; engine {state}", { key: key, state: engineStateLabel(state.engine) })
      : t("{key} changed to {value2}", { key: key, value2: checked ? "on" : "off" }));
    return true;
  } catch (error) {
    state.toggles[key] = previous;
    if (key === "startAtLogin") {
      try {
        await loadSettingsSnapshot();
      } catch (refreshError) {
        appendLog("error", "settings", t("Could not refresh the Login Item state after refusal: {error}", { error: errorText(refreshError) }));
      }
    }
    if (isEngineMutation) {
      try {
        await loadEngineStatus();
      } catch (refreshError) {
        appendLog("error", "engine", t("Could not refresh mode state after refusal: {error}", { error: errorText(refreshError) }));
      }
      state.engineMutationError = errorText(error).slice(0, 512);
    }
    throw error;
  } finally {
    if (isEngineMutation) {
      state.engineMutationBusy = false;
      renderPage();
    }
  }
}

export async function handleAction(action) {
  if (action === "open-automation-settings") { await automationSettingsUI.open(); return; }
  if (action === "open-runtime-settings") { await runtimeSettingsUI.open(); return; }
  if (action === "open-legacy-maintenance") {
    await loadRetirementStatus();
    state.legacyMaintenanceOpen = true;
    state.activePage = "general";
    await invoke("open_page", { page: "general" });
    renderPage();
    return;
  }
  if (action === "close-legacy-maintenance") {
    if (!state.migrationHandoff) state.legacyMaintenanceOpen = false;
    renderPage();
    return;
  }
  if (action === "reload-dashboard") {
    await reloadPayload();
    return;
  }
  if (action === "open-settings") {
    state.activePage = "settings";
  }
  if (action === "open-migration-profiles") {
    state.activePage = "profiles";
    await invoke("open_page", { page: "profiles" });
    renderPage();
    return;
  }
  if (action === "begin-migration-handoff") {
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
  }
  if (action === "prepare-cutover") {
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
  }
  if (action === "confirm-cutover") {
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
  }
  if (action === "recover-cutover") {
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
  }
  if (action === "scroll-to-selected-proxy") {
    const group = activeProxyGroup();
    const selected = group?.now;
    if (!selected) {
      appendLog("warning", "proxy", t("No selected proxy to scroll to"));
      return;
    }
    state.toggles.showProxiesList = true;
    state.proxyFilter = "";
    state.proxyGroupHideTimeouts.set(group.name, false);
    state.proxyBlinkNode = selected;
    revealSelectedProxy(selected);
    renderPage();
    requestAnimationFrame(() => {
      const card = document.querySelector(`[data-proxy-node="${CSS.escape(selected)}"]`);
      card?.scrollIntoView({ block: "center", behavior: "smooth" });
    });
    setTimeout(() => {
      if (state.proxyBlinkNode === selected) {
        state.proxyBlinkNode = null;
        if (state.activePage === "proxies") renderPage();
      }
    }, 1200);
  }
  if (action === "toggle-hide-timed-out") {
    const group = activeProxyGroup();
    if (group) state.proxyGroupHideTimeouts.set(group.name, !hideTimedOutProxies(group));
  }
  if (action === "toggle-hide-unavailable") {
    state.toggles.hideUnavailable = !state.toggles.hideUnavailable;
    state.proxyGroupHideTimeouts.clear();
  }
  if (action === "toggle-show-proxies") {
    state.toggles.showProxiesList = !(state.toggles.showProxiesList !== false);
  }
  if (action === "toggle-proxy-filter") {
    state.toggles.showProxyFilter = !state.toggles.showProxyFilter;
    if (!state.toggles.showProxyFilter) state.proxyFilter = "";
  }
  if (action === "break-proxy-connections") {
    if (!controllerActionAllowed(t("Breaking proxy connections"), "proxy")) return;
    const token = captureEngineIdentityToken();
    const count = state.connections.length;
    try {
      await invoke("close_all_connections");
      if (!engineIdentityTokenIsCurrent(token)) return;
      appendLog("warning", "proxy", t("Broke {count} connection(s)", { count: count }));
      await loadControllerSnapshot(true, token);
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return;
      appendLog("error", "proxy", t("Break connections failed: {error}", { error: errorText(error) }));
    }
  }
  if (action === "open-providers") {
    state.activePage = "providers";
  }
  if (action === "open-rules") {
    state.activePage = "rules";
    await loadRulesSnapshot();
  }
  if (action === "close-all") {
    if (!controllerActionAllowed(t("Closing all connections"), "connection")) return;
    const token = captureEngineIdentityToken();
    const count = state.connections.length;
    state.closingAllConnections = true;
    renderPage();
    try {
      await invoke("close_all_connections");
      if (!engineIdentityTokenIsCurrent(token)) return;
      appendLog("warning", "connection", t("Closed {count} active connections", { count: count }));
      await loadControllerSnapshot(true, token);
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return;
      state.controllerStatus = "controller offline";
      appendLog("error", "connection", t("Controller close-all failed; keeping local rows: {error}", { error: errorText(error) }));
    } finally {
      if (engineIdentityTokenIsCurrent(token)) state.closingAllConnections = false;
    }
  }
  if (action === "delay-test") {
    await runProxyDelayTest();
  }
  if (action === "reload-proxies") {
    if (!controllerActionAllowed(t("Reloading proxies"), "proxy")) return;
    const live = await loadControllerSnapshot();
    appendLog(live ? "info" : "error", "proxy", live ? "Controller snapshot reloaded" : t("Controller unavailable; keeping local data"));
  }
  if (action === "copy-proxy-exports") {
    const port = state.projection.mixedPort;
    if (!port) {
      appendLog("warning", "shell", t("The projected inbound port is unavailable: {value1}", { value1: state.projection.error ?? "no active profile is selected" }));
      renderPage();
      return;
    }
    const exports = [
      `export https_proxy=http://127.0.0.1:${port}`,
      `export http_proxy=http://127.0.0.1:${port}`,
      `export all_proxy=socks5://127.0.0.1:${port}`,
    ].join("\n");
    try {
      await navigator.clipboard.writeText(exports);
      appendLog("info", "shell", t("Copied proxy export commands for Terminal"));
    } catch (error) {
      appendLog("warning", "clipboard", errorText(error));
    }
  }
  if (action === "allow-lan-info") {
    state.glassDialog = {
      kind: "info",
      payload: {
        title: t("Allow LAN"),
        body: REASONS.allowLan,
      },
    };
    renderGlassOverlays();
    return;
  }
  if (action === "show-network-interfaces") {
    try {
      const diagnostics = await invoke("network_diagnostics");
      state.networkDiagnostics = diagnostics;
      state.glassDialog = {
        kind: "network-services",
        payload: diagnostics?.services ?? [],
        unavailable: diagnostics?.unavailable ?? [],
      };
      renderGlassOverlays();
      return;
    } catch (error) {
      appendLog("error", "network", errorText(error));
    }
  }
  if (action === "preview-runtime-config") {
    if (!runtimeProjectionActionAllowed(t("Configuration preview"))) return;
    try {
      const body = await invoke("read_runtime_config_text");
      state.glassDialog = { kind: "preview-config", payload: body };
      renderGlassOverlays();
      return;
    } catch (error) {
      appendLog("error", "engine", t("Configuration preview failed: {error}", { error: errorText(error) }));
    }
  }
  if (action === "dns-query") {
    state.glassDialog = { kind: "dns-query", payload: { name: "www.gstatic.com", type: "A", result: "" } };
    renderGlassOverlays();
    return;
  }
  if (action === "tun-info") {
    state.glassDialog = {
      kind: "info",
      payload: {
        title: t("TUN Mode"),
        body: t("TUN Mode runs the packet tunnel as a signed NetworkExtension System Extension. macOS asks for approval once, under System Settings › General › Login Items & Extensions; until it is approved the switch stays unavailable."),
      },
    };
    renderGlassOverlays();
    return;
  }
  if (action === "mixin-info") {
    state.glassDialog = {
      kind: "info",
      payload: {
        title: t("Mixin"),
        body: REASONS.mixin,
      },
    };
    renderGlassOverlays();
    return;
  }
  if (action === "open-home-directory") {
    try {
      await invoke("reveal_home_directory");
      appendLog("info", "shell", t("Home Directory opened in Finder"));
    } catch (error) {
      appendLog("error", "shell", t("Open Folder failed: {error}", { error: errorText(error) }));
    }
  }
  if (action === "retry-system-proxy") {
    await applyToggle("systemProxy", true, "explicit retry");
    renderPage();
  }
  if (action === "toggle-core") {
    await applyToggle("coreRunning", state.engine.desiredMode === "off", "core");
    renderPage();
  }
  if (action === "cancel-system-proxy" || action === "cancel-tun-mode") {
    await applyToggle(action === "cancel-system-proxy" ? "systemProxy" : "tunMode", false, "cancel request");
    renderPage();
  }
  if (action === "retry-tun-mode") {
    try {
      const admitted = await applyToggle("tunMode", true, "explicit retry");
      if (!admitted) {
        renderPage();
        return;
      }
      if (state.engine.state === "AwaitingApproval") {
        await invoke("open_login_items_settings");
        appendLog("info", "shell", t("Opened System Settings › General › Login Items & Extensions"));
      }
    } catch (error) {
      appendLog("error", "engine", t("TUN retry failed: {error}", { error: errorText(error) }));
    }
    renderPage();
  }
  if (action === "tun-restore-dns-info") {
    state.glassDialog = {
      kind: "info",
      payload: { title: t("System DNS"), body: REASONS.restoreDns },
    };
    renderGlassOverlays();
    return;
  }
  if (action === "preview-credential-gc") {
    try {
      const preview = normalizeCredentialGcPreview(await invoke("preview_credential_gc"));
      state.credentialGcPreview = preview.orphanCount ? preview : null;
      state.glassDialog = { kind: "credential-cleanup" };
      renderGlassOverlays();
      return;
    } catch (error) {
      appendLog("error", "credentials", errorText(error));
    }
  }
  if (action === "update-profile-from-inspector") {
    const id = state.profileInspector?.profile?.id ?? state.profileInspector?.id;
    if (!id) {
      appendLog("warning", "profile", t("No profile is open"));
    } else {
      await runProfileMenuAction("update", id);
      await openProfileInspector(id, "edit");
    }
  }
  if (action === "import-profile") {
    const input = document.querySelector("[data-profile-url]");
    const url = input?.value?.trim();
    if (!url) {
      appendLog("warning", "profile", t("A subscription URL or node link is required before import"));
    } else {
      const subscription = isSubscriptionSource(url);
      const result = subscription
        ? await invokeProfileChange("import_profile_url", { url, name: null, activate: true })
        : await invokeProfileChange("import_profile_text", { name: null, body: url });
      input.value = "";
      await loadProfilesSnapshot();
      appendLog("info", "profile", t("Profile imported: {name} ({value2})", { name: result.name, value2: formatBytes(result.bytes ?? 0) }));
      if (!subscription) {
        await selectProfileById(result.id);
      }
      await openCredentialSetup(result.id);
    }
  }
  if (action === "paste-profile-url") {
    const input = document.querySelector("[data-profile-url]");
    try {
      const text = await navigator.clipboard.readText();
      if (input) input.value = text.trim();
      appendLog("info", "profile", t("Profile URL pasted from clipboard"));
    } catch (_error) {
      appendLog("warning", "profile", t("Clipboard read was refused"));
    }
  }
  if (action === "import-profile-file") {
    const input = document.querySelector("[data-profile-file]");
    const file = input?.files?.[0];
    if (!file) {
      input?.click();
      return;
    }
    try {
      const body = await readProfileSourceFile(file);
      const result = await invokeProfileChange("import_profile_text", { name: file.name, body });
      await loadProfilesSnapshot();
      appendLog("info", "profile", t("Local profile imported: {name} ({value2})", { name: result.name, value2: formatBytes(result.bytes ?? 0) }));
      await selectProfileById(result.id);
      await openCredentialSetup(result.id);
    } finally {
      input.value = "";
    }
  }
  if (action === "migrate-legacy-profiles") {
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
  }
  if (action === "update-all-profiles") {
    let updated = 0;
    let failed = 0;
    let local = 0;
    let cleanupPending = 0;
    // A profile list never carries a subscription URL, so each profile is read
    // once here, on this explicit user action, to find the remote ones.
    for (const profile of [...state.profiles]) {
      if (!(await resolveProfileSource(profile.id))) {
        local += 1;
        continue;
      }
      try {
        const result = await invokeProfileChange("update_profile", { id: profile.id });
        updated += 1;
        if (result.credential_cleanup_pending) {
          cleanupPending += 1;
          appendLog(
            "warning",
            "profile",
            t("{name} updated. Old credentials are retained for recovery.{value2}", { name: profile.name, value2: result.credential_cleanup_error ? t(" Cleanup: {error}", { error: result.credential_cleanup_error }) : "" }),
          );
        }
      } catch (error) {
        failed += 1;
        appendLog("error", "profile", t("Update failed for {name}: {error}", { name: profile.name, error: errorText(error) }));
      }
    }
    await loadProfilesSnapshot();
    appendLog(
      failed ? "error" : "info",
      "profile",
      t("Update All completed: {updated} updated{value2}{value3}{value4}", { updated: updated, value2: failed ? t(", {count} failed", { count: failed }) : "", value3: cleanupPending ? t(", {count} cleanup pending", { count: cleanupPending }) : "", value4: local ? t(", {count} without a subscription URL", { count: local }) : "" }),
    );
  }
  if (action === "save-profile-editor") {
    const editor = document.querySelector("[data-profile-editor]");
    const inspector = state.profileInspector;
    if (!editor || !inspector?.profile?.id) {
      appendLog("warning", "profile", t("No profile editor is open"));
    } else {
      const result = await invokeProfileChange("save_profile_text", { id: inspector.profile.id, expectedDigest: inspector.profile.digest, body: editor.value });
      await loadProfilesSnapshot();
      appendLog("info", "profile", t("Profile JSON saved: {value1}", { value1: formatBytes(result.bytes ?? 0) }));
      await openProfileInspector(result.id, "edit");
      await openCredentialSetup(result.id);
    }
  }
  if (action === "close-profile-inspector") {
    state.profileInspector = null;
  }
  if (action === "update-all-providers" || action === "health-check-all") {
    await handleProviderAction(action);
    return;
  }
  if (action === "flush-fake-ip-cache") {
    if (!controllerActionAllowed(t("Fake IP cache flush"), "cache")) return;
    const token = captureEngineIdentityToken();
    try {
      await invoke("flush_fake_ip_cache");
      if (!engineIdentityTokenIsCurrent(token)) return;
      appendLog("info", "cache", t("Fake IP cache flushed through the engine controller"));
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return;
      state.controllerStatus = "controller offline";
      appendLog("error", "cache", t("Fake IP cache flush failed: {error}", { error: errorText(error) }));
    }
  }
  if (action === "reload-rules") {
    if (!controllerActionAllowed(t("Rules reload"), "rules")) return;
    const loaded = await loadRulesSnapshot();
    appendLog(loaded ? "info" : "error", "rules", loaded ? t("Loaded {count} controller rules", { count: state.rules.length }) : t("Rules controller endpoint unavailable"));
  }
  if (action === "toggle-log-stream") {
    const pause = !state.logsPaused;
    if (!pause && !controllerActionAllowed(t("Starting request logs"), "logs")) return;
    const previous = state.logsPaused;
    state.logsPaused = pause;
    try {
      const changed = await setLogStreamRunning(!pause);
      if (!changed) return;
      appendLog("info", "logs", t("Request logs {value1}", { value1: pause ? "stopped" : "started" }));
    } catch (error) {
      if (!pause) state.logsPaused = previous;
      appendLog("error", "logs", t("Log stream change failed: {error}", { error: errorText(error) }));
    }
  }
  if (action === "clear-logs") {
    state.logs = [];
  }
  if (action === "copy-logs") {
    const text = state.logs.map((entry) => {
      const time = entry.time ?? entry.at ?? "";
      const level = entry.level ?? "info";
      const message = entry.message ?? entry.payload ?? String(entry);
      return `[${time}] ${level} ${message}`;
    }).join("\n");
    try {
      await navigator.clipboard.writeText(text || "(no logs)");
      appendLog("info", "logs", t("Copied {count} log line(s) to clipboard", { count: state.logs.length }));
    } catch (error) {
      appendLog("warning", "logs", t("Copy logs refused: {error}", { error: errorText(error) }));
    }
  }
  if (action === "reveal-logs") {
    try {
      await invoke("reveal_logs_directory");
      appendLog("info", "logs", t("Logs folder opened in Finder"));
    } catch (error) {
      appendLog("error", "logs", t("Open Folder failed: {error}", { error: errorText(error) }));
    }
  }
  if (action === "toggle-connection-stream") {
    const pause = !state.connectionPaused;
    if (!pause && !controllerActionAllowed(t("Starting connection stream"), "connections")) return;
    const previous = state.connectionPaused;
    state.connectionPaused = pause;
    try {
      const changed = await setConnectionsStreamRunning(!pause);
      if (!changed) return;
      appendLog("info", "connections", t("Connection stream {value1}", { value1: pause ? "stopped" : "started" }));
    } catch (error) {
      if (!pause) state.connectionPaused = previous;
      appendLog("error", "connections", t("Connection stream change failed: {error}", { error: errorText(error) }));
    }
  }
  if (action === "close-connection-detail") {
    state.connectionDetailId = null;
  }
  if (action === "clear-connection-search") {
    state.connectionSearch = "";
  }
  if (action === "save-settings") {
    if (state.settingsUnavailableReason) throw new Error(state.settingsUnavailableReason);
    const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
    applyPersistedSettings(snapshot);
    appendLog("info", "settings", t("Preferences saved"));
  }
  if (action === "check-for-updates") {
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
  }
  if (action === "reload-settings") {
    await loadSettingsSnapshot();
    appendLog("info", "settings", t("Preferences reloaded from disk"));
  }
  if (action === "reset-settings") {
    if (state.settingsUnavailableReason) throw new Error(state.settingsUnavailableReason);
    // WKWebView often swallows window.confirm — use in-app glass dialog.
    state.glassDialog = { kind: "reset-settings" };
    renderGlassOverlays();
    return;
  }
  if (action === "quit-app") {
    await invoke("quit_app");
    return;
  }
  if (action === "force-quit-app") {
    await invoke("force_quit_app");
    return;
  }
  renderPage();
}

function appendLog(level, source, message) {
  state.logs = withLogRow(state.logs, logEntry(level, source, message));
}

function appendLogLines(lines) {
  const normalized = (Array.isArray(lines) ? lines : []).map((line) => logEntry(
    line.level,
    line.source ?? "engine",
    line.message ?? "",
    line.time ?? "live",
    line.fields,
  ));
  state.logs = withLogRows(state.logs, normalized);
}

async function closeConnectionsAfterProxyChange(
  reason,
  token = captureEngineIdentityToken(),
  publishAllowed = () => true,
) {
  if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
  const count = state.connections.length;
  if (!count) return true;
  try {
    await invoke("close_all_connections");
    if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
    state.connections = [];
    state.connectionStream.rows = new Map();
    appendLog("warning", "connection", t("Closed {count} connection(s) after {reason} switch", { count: count, reason: reason }));
    return true;
  } catch (error) {
    if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
    state.controllerStatus = "controller offline";
    appendLog("error", "connection", t("Connection cleanup after {reason} switch failed: {error}", { reason: reason, error: errorText(error) }));
    return false;
  }
}

async function openProfileInspector(id, mode, focusKey = null) {
  const profile = await invoke("read_profile_text", { id });
  const inspector = { id, mode, profile, focusKey };
  if (mode === "qrcode") {
    try {
      inspector.svg = await invoke("profile_qrcode_svg", { id });
    } catch (error) {
      inspector.error = errorText(error);
      appendLog("error", "profile", t("Could not render the profile QR code: {error}", { error: inspector.error }));
    }
  }
  state.profileInspector = inspector;
}

function focusProfileEditorSection(key) {
  if (!key) return;
  const editor = document.querySelector("[data-profile-editor]");
  if (!(editor instanceof HTMLTextAreaElement)) return;
  const body = editor.value;
  const match = body.match(new RegExp(`"${key}"\\s*:`, "m"));
  if (!match || match.index == null) return;
  const start = match.index;
  editor.focus();
  editor.setSelectionRange(start, start + match[0].length);
  const before = body.slice(0, start);
  const line = before.split("\n").length - 1;
  const lineHeight = Number.parseFloat(getComputedStyle(editor).lineHeight) || 18;
  editor.scrollTop = Math.max(0, line * lineHeight - 40);
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

function markHandoffStatusUnverifiable(error) {
  state.migrationHandoffStatus = {
    state: "failed",
    code: "migration_handoff_task_failed",
    message: t("Migration handoff status could not be verified. Review the application log before retrying."),
  };
  appendLog("error", "migration", t("Migration handoff state could not be trusted: {error}", { error: errorText(error) }));
}

async function loadBootPayload() {
  applyBootPayload(await invoke("boot_payload"));
}

async function acknowledgeMigrationHandoffRendererReady() {
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

/// Applies an engine status envelope, validating the runtime identity before the
/// dashboard is allowed to say the network is up.
function applyEngineStatus(payload) {
  const previous = state.engine;
  let next;
  try {
    next = normalizeEngineStatus(payload);
  } catch (error) {
    next = { ...defaultEngineStatus, availabilityReason: errorText(error) };
    appendLog("error", "engine", t("Engine state could not be trusted: {error}", { error: errorText(error) }));
  }
  state.engine = next;
  if (engineRuntimeIdentityChanged(previous, next)) {
    invalidateEngineBoundState(next.active);
  } else if (!next.active) {
    // Off is an expected steady state. Repeated snapshots still clear any
    // event/request result that arrived between native status reads.
    clearControllerBackedState();
      state.controllerVersion = null;
    state.controllerStatus = "engine off";
  }
  // Green switches represent verified runtime activity. Pending and failed
  // intentions retain separate retry/cancel actions and never look connected.
  state.toggles.systemProxy = state.engine.systemProxyActive;
  state.toggles.tunMode = state.engine.tunnelActive;
  if (state.engine.active) {
    if (!state.engineStartedAt) state.engineStartedAt = Date.now();
    state.traffic.runtimeSeconds = Math.floor((Date.now() - state.engineStartedAt) / 1000);
  } else {
    state.engineStartedAt = null;
    state.traffic.runtimeSeconds = 0;
  }
  updateStatusBar();
}

async function loadEngineStatus() {
  const requestId = runtime.engineStatusRequestId + 1;
  runtime.engineStatusRequestId = requestId;
  try {
    const snapshot = await invoke("engine_snapshot");
    if (requestId !== runtime.engineStatusRequestId) return false;
    applyEngineStatus(snapshot);
  } catch (error) {
    if (requestId !== runtime.engineStatusRequestId) return false;
    state.engine = { ...defaultEngineStatus, availabilityReason: errorText(error) };
    invalidateEngineBoundState(false);
    appendLog("error", "engine", t("Unable to read the engine state: {error}", { error: errorText(error) }));
  }
  try {
    state.geoipStatus = await invoke("geoip_database_status");
  } catch (error) {
    state.geoipStatus = null;
    appendLog("error", "geoip", t("Unable to read the GeoIP database status: {error}", { error: errorText(error) }));
  }
  if (state.engine.active) {
    const token = captureEngineIdentityToken();
    try {
      const version = await invoke("controller_version");
      if (engineIdentityTokenIsCurrent(token)) state.controllerVersion = version;
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return false;
      state.controllerVersion = null;
      appendLog("error", "controller", t("Unable to read the controller version: {error}", { error: errorText(error) }));
    }
  } else {
    state.controllerVersion = null;
  }
  return true;
}

/// Reads optional maintenance and unfinished-operation status. Network start
/// admission belongs to the engine; unreadable maintenance state remains
/// visible rather than being represented as completed cleanup.
async function loadRetirementStatus() {
  try {
    state.retirement = normalizeRetirementStatus(await invoke("legacy_retirement_status"));
  } catch (error) {
    state.retirement = unverifiableRetirementStatus(errorText(error));
    appendLog("error", "engine", t("Unable to read the legacy retirement state: {error}", { error: errorText(error) }));
  }
}

async function loadPlatformDesign() {
  try {
    state.platform = await invoke("current_platform_design");
  } catch (error) {
    state.platform = null;
    appendLog("error", "shell", t("Unable to read the platform design: {error}", { error: errorText(error) }));
  }
}

/// Reads the projected engine configuration so the dashboard can show the real
/// inbound and controller endpoint instead of a remembered preference. Without a
/// selected profile there is no projection, which is reported, not invented.
async function loadRuntimeProjection() {
  // Effective DNS may change with the selected profile even when the saved
  // user preferences have not changed.
  await runtimeSettingsUI.load();
  if (state.profilesUnavailableReason) {
    state.projection = {
      mixedPort: null,
      listenAddress: null,
      controller: null,
      logLevel: null,
      error: t("profile state is unavailable: {profilesUnavailableReason}", { profilesUnavailableReason: state.profilesUnavailableReason }),
    };
    return false;
  }
  if (!state.profiles.some((profile) => profile.active === true)) {
    state.projection = {
      mixedPort: null,
      listenAddress: null,
      controller: null,
      logLevel: null,
      error: "no active profile is selected",
    };
    return false;
  }
  try {
    const document = JSON.parse(await invoke("read_runtime_config_text"));
    const inbound = (document.inbounds ?? []).find((entry) => entry?.type === "mixed" && entry?.tag === "cfw-system-proxy");
    state.projection = {
      mixedPort: Number.isInteger(inbound?.listen_port) ? inbound.listen_port : null,
      listenAddress: typeof inbound?.listen === "string" ? inbound.listen : null,
      controller: document.experimental?.clash_api?.external_controller ?? null,
      logLevel: document.log?.disabled === true ? "silent" : document.log?.level ?? null,
      error: null,
    };
    return true;
  } catch (error) {
    state.projection = {
      mixedPort: null,
      listenAddress: null,
      controller: null,
      logLevel: null,
      error: errorText(error),
    };
    appendLog("error", "profile", t("Active profile projection could not be read: {error}", { error: state.projection.error }));
    return false;
  }
}

async function loadSettingsSnapshot(includeLiveStatus = true) {
  const snapshot = includeLiveStatus
    ? await invoke("read_settings_snapshot")
    : await invoke("read_settings_snapshot", { includeLoginItemStatus: false });
  applyPersistedSettings(snapshot);
  return snapshot;
}

async function refreshStartupLoginItemStatus(expectedSettings) {
  try {
    const snapshot = await invoke("read_settings_snapshot");
    if (state.settingsSnapshot === expectedSettings) applyPersistedSettings(snapshot);
  } catch {
    if (state.settingsSnapshot === expectedSettings) {
      state.launchAtLogin.observationError = "macOS Login Item status could not be read. Reload to retry; the failure is recorded in local diagnostics.";
      appendLog("warning", "settings", state.launchAtLogin.observationError);
    }
  }
  if (["general", "settings"].includes(state.activePage)) renderPage();
}

async function loadNetworkDiagnostics() {
  try {
    state.networkDiagnostics = await invoke("network_diagnostics");
  } catch (error) {
    state.networkDiagnostics = null;
    appendLog("error", "network", t("Unable to inspect macOS network services: {error}", { error: errorText(error) }));
  }
}

function resetControllerStateForInactiveEngine() {
  clearControllerBackedState();
  state.controllerStatus = "engine off";
}

async function loadControllerSnapshot(
  reportFailure = true,
  token = captureEngineIdentityToken(),
  publishAllowed = () => true,
  observe = null,
) {
  if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) {
    if (!state.engine.active) resetControllerStateForInactiveEngine();
    return false;
  }
  try {
    const snapshot = await invoke("controller_snapshot");
    if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
    if (!snapshot) {
      clearControllerBackedState();
      state.controllerStatus = "controller offline";
      if (reportFailure) appendLog("error", "controller", t("Running engine returned no controller snapshot"));
      return false;
    }
    if (observe) observe(snapshot);
    applyControllerSnapshot(snapshot);
    applyPendingControllerIntents();
    invoke("refresh_tray_menu").catch((error) => {
      if (engineIdentityTokenIsCurrent(token) && publishAllowed()) {
        appendLog("error", "tray", t("Tray refresh failed: {error}", { error: errorText(error) }));
      }
    });
    return true;
  } catch (error) {
    if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
    clearControllerBackedState();
    state.controllerStatus = "controller offline";
    if (reportFailure) appendLog("error", "controller", errorText(error));
    return false;
  }
}

async function loadControllerSnapshotWithRetry(attempts = 4, delayMs = 600) {
  const token = captureEngineIdentityToken();
  if (!engineIdentityTokenIsCurrent(token)) {
    resetControllerStateForInactiveEngine();
    return false;
  }
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (!engineIdentityTokenIsCurrent(token)) return false;
    const finalAttempt = attempt + 1 === attempts;
    if (await loadControllerSnapshot(finalAttempt, token)) return true;
    if (!engineIdentityTokenIsCurrent(token)) return false;
    if (attempt + 1 < attempts) await sleep(delayMs);
  }
  return false;
}

/// Nothing controller-backed survives an unreachable controller: an empty page
/// is honest, stale proxy groups are not.
function clearControllerBackedState() {
  state.mode = null;
  state.logLevel = null;
  state.toggles.allowLan = false;
  state.proxyGroups = [];
  state.activeProxyGroup = null;
  state.proxyBlinkNode = null;
  state.connections = [];
  state.rules = [];
  state.connectionStream = {
    at: 0,
    uploadTotal: 0,
    downloadTotal: 0,
    rows: new Map(),
  };
  state.traffic.upload = 0;
  state.traffic.download = 0;
  state.connectionDetailId = null;
  state.closingConnectionIds.clear();
  state.closingAllConnections = false;
}


async function loadRulesSnapshot(token = captureEngineIdentityToken()) {
  if (!engineIdentityTokenIsCurrent(token)) {
    if (!state.engine.active) state.rules = [];
    return false;
  }
  try {
    const snapshot = await invoke("rules_snapshot");
    if (!engineIdentityTokenIsCurrent(token)) return false;
    const rules = Array.isArray(snapshot?.rules) ? snapshot.rules : [];
    state.rules = rules.map((rule) => ({
      index: rule.index == null ? "unavailable" : String(rule.index),
      type: rule.kind ?? rule.type ?? "",
      payload: rule.payload ?? "",
      proxy: rule.proxy ?? "",
      provider: rule.provider ?? "",
      hits: rule.hits == null ? "unavailable" : String(rule.hits),
      size: rule.size ?? "unavailable",
      extra: rule.extra ?? {},
    }));
    return true;
  } catch (error) {
    if (!engineIdentityTokenIsCurrent(token)) return false;
    state.rules = [];
    appendLog("error", "rules", errorText(error));
    return false;
  }
}

async function loadSavedProfilePolicy() {
  if (state.toggles.testingDelays) cancelDelayTest();
  const previous = state.savedProfilePolicy;
  const previousBody = runtime.savedProfilePolicyBody;
  const epoch = ++runtime.savedProfilePolicyEpoch;
  const active = state.profiles.find((profile) => profile.active);
  state.savedProfilePolicy = null;
  state.savedProfilePolicyError = null;
  if (!active) return;
  try {
    const text = await invoke("read_profile_text", { id: active.id });
    if (epoch !== runtime.savedProfilePolicyEpoch) return;
    if (text?.id !== active.id) throw new TypeError("saved profile identity changed");
    state.savedProfilePolicy = savedProfilePolicy(text);
    if (previous?.profileId !== text.id || previousBody !== text.body) {
      cancelDelayTest();
      state.proxyDelayResults.clear();
      state.proxyGroupHideTimeouts.clear();
      state.proxyDelayMessage = null;
    }
    runtime.savedProfilePolicyBody = text.body;
    for (const group of state.savedProfilePolicy.groups) {
      for (const node of group.options) {
        const measured = state.proxyDelayResults.get(node.name);
        if (measured) Object.assign(node, measured);
      }
    }
  } catch (error) {
    if (epoch !== runtime.savedProfilePolicyEpoch) return;
    state.savedProfilePolicyError = errorText(error);
    appendLog("error", "profile", state.savedProfilePolicyError);
  }
}

async function loadProfilesSnapshot() {
  try {
    const profiles = await invoke("profiles_snapshot");
    if (!Array.isArray(profiles)) throw new TypeError("profile snapshot is not an array");
    for (const profile of profiles) {
      if (profile.source_kind !== "local" && profile.source_kind !== "subscription") {
        throw new TypeError("profile snapshot has an invalid source kind");
      }
    }
    const previousProfileId = state.profiles.find((profile) => profile.active)?.id ?? null;
    const known = new Map(state.profiles.map((profile) => [profile.id, profile]));
    state.profiles = profiles.map((profile) => ({
      id: profile.id,
      name: profile.name,
      updated: profile.updated_epoch_secs
        ? formatRelativeUpdated(profile.updated_epoch_secs)
        : "unknown",
      updatedEpochSecs: profile.updated_epoch_secs ?? null,
      sourceKind: profile.source_kind,
      active: Boolean(profile.active),
      // A profile list carries no subscription URL, because it can bear an
      // access token. `undefined` means "not published in a list"; it is
      // resolved by an explicit single-profile read.
      sourceUrl: known.get(profile.id)?.sourceUrl,
      sourceError: known.get(profile.id)?.sourceError ?? null,
    }));
    if (previousProfileId !== (state.profiles.find((profile) => profile.active)?.id ?? null)) providerSelectionChanged();
    state.profilesUnavailableReason = null;
    await loadSavedProfilePolicy();
    await loadProvidersSnapshot();
    if (state.credentialSetup && !state.profiles.some(({ id }) => id === state.credentialSetup.profileId)) {
      state.credentialSetup = null;
    }
    return true;
  } catch (error) {
    state.profiles = [];
    providerSelectionChanged();
    runtime.savedProfilePolicyEpoch += 1;
    state.savedProfilePolicy = null;
    state.savedProfilePolicyError = errorText(error);
    state.profilesUnavailableReason = errorText(error);
    appendLog("error", "profile", state.profilesUnavailableReason);
    return false;
  }
}

async function startLiveStreams() {
  const engineEpoch = runtime.engineIdentityEpoch;
  const running = Boolean(state.engine.active);
  const streams = [
    ["connections", () => setConnectionsStreamRunning(running && !state.connectionPaused)],
    ["logs", () => setLogStreamRunning(running && !state.logsPaused)],
  ];
  for (const [name, apply] of streams) {
    if (engineEpoch !== runtime.engineIdentityEpoch) return;
    try {
      await apply();
      if (engineEpoch !== runtime.engineIdentityEpoch) return;
    } catch (error) {
      if (engineEpoch !== runtime.engineIdentityEpoch) return;
      appendLog("error", name, t("Live stream unavailable: {error}", { error: errorText(error) }));
    }
  }
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

  await listen("cfw://page", (event) => {
    state.activePage = event.payload;
    renderPage();
  });

  await listen("cfw://settings-changed", async (event) => {
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
  });

  await listen("cfw://update-available", (event) => {
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
  });

  await listen("cfw://connections-snapshot", (event) => {
    if (state.connectionPaused) return;
    const payload = validatedStreamEventPayload(
      event.payload,
      runtime.connectionsLiveStream.binding,
      "connections",
    );
    if (payload === undefined) return;
    applyConnectionsSnapshot(payload);
    updateStatusBar();
    if (state.activePage === "connections") {
      scheduleConnectionsPatch();
    } else if (state.activePage === "general") {
      scheduleRender();
    }
  });

  // Emitted with no payload when the legacy-retirement gate changes what the
  // engine is allowed to do, so the capability reason on General is re-read
  // instead of going stale.
  await listen("cfw://engine-snapshot", async () => {
    await loadEngineStatus();
    await loadRetirementStatus();
    await startLiveStreams();
    renderPage();
  });

  await listen("cfw://engine-event", async (event) => {
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
  });

  await listen("cfw://log-lines", (event) => {
    if (state.logsPaused) return;
    const payload = validatedStreamEventPayload(
      event.payload,
      runtime.logLiveStream.binding,
      "request-logs",
    );
    if (payload === undefined) return;
    appendLogLines(payload);
    if (state.activePage === "logs") scheduleLogStreamPatch();
  });

  await listen("cfw://stream-error", (event) => {
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
  });

  await listen("tauri://drag-drop", async (event) => {
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
  });

  criticalMigrationListenersBound = true;
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

  window.setInterval(() => {
    if (state.engine.active) {
      if (!state.engineStartedAt) state.engineStartedAt = Date.now();
      state.traffic.runtimeSeconds = Math.floor((Date.now() - state.engineStartedAt) / 1000);
    } else {
      state.engineStartedAt = null;
      state.traffic.runtimeSeconds = 0;
    }
    updateStatusBar();
  }, 1000);
}

async function importProfileFromPath(path) {
  try {
    const result = await invokeProfileChange("import_profile_file", { path, name: null, activate: true });
    await loadProfilesSnapshot();
    appendLog("info", "profile", t("Dropped profile imported: {name} ({value2})", { name: result.name, value2: formatBytes(result.bytes ?? 0) }));
    await openCredentialSetup(result.id);
    scheduleRender();
  } catch (error) {
    appendLog("error", "profile", t("Drag-drop import failed: {error}", { error: errorText(error) }));
  }
}

export function renderFatalBootstrap() {
  if (window.__CFM_STARTUP__) {
    window.__CFM_STARTUP__.fail();
    return;
  }
  document.body.innerHTML = `<pre class="fatal">${escapeHtml(t("Clash for Mac could not start safely (startup_state_unverifiable). Review the application log before retrying."))}</pre>`;
}

bootstrap().catch(() => {
  renderFatalBootstrap();
});
