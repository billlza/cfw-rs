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
  tunnelValueLabel,
  formatGeoipLabel,
  formatBytes,
  formatRate,
  formatRelativeUpdated,
  delayFailureLabel,
  providerActionKey,
  providerBatchSummary,
  providerBatchSucceeded,
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
  migrationHandoffRendererAckArguments,
  migrationRoute,
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

const LOGIN_ITEM_LIVE_STATUSES = new Set([
  "enabled",
  "not_registered",
  "not_found",
  "requires_approval",
  "unknown",
]);
const SETTINGS_FIELDS = Object.freeze([
  "check_for_updates",
  "font_family",
  "launch_at_login",
  "retain_window_bounds",
  "silent_start",
  "theme",
]);
const PROVIDER_CAPABILITY_UNSUPPORTED_PREFIX = "controller capability `provider management` is unsupported";
const PROVIDER_CAPABILITY_UNAVAILABLE = "Provider management is unavailable in the pinned sing-box 1.13.15 engine.";

/// Reasons the dashboard shows next to a control the 0.4.0 backend refuses.
/// Each one states what the product does instead, so a disabled switch is never
/// unexplained and never silently does nothing.
const REASONS = Object.freeze({
  allowLan: "LAN exposure is unavailable: the projected mixed inbound is bound to loopback and a running engine cannot be rebound.",
  bindAddress: "The mixed inbound address is fixed by the projected configuration and cannot be changed in this build.",
  logLevel: "The projected configuration pins the engine log level to info and the engine controller accepts no log-level change.",
  mixin: "Mixin is unavailable: the engine configuration is projected by the app, and an imported document may only describe routing and outbound policy.",
  geoip: "No GeoIP database can be downloaded: the accepted profile subset contains no rule set or GeoIP matcher, so this engine consumes no GeoIP database.",
  restoreDns: "This app never writes host DNS, because the legacy restore value carries no per-service ownership identity. Clear or set custom DNS per service in System Settings › Network › Details › DNS.",
  engineNotOff: "Profile changes require the engine to be Off. Turn System Proxy and TUN Mode off first.",
  quota: "Subscription quota headers are not retained by this build.",
  listSource: "A profile list never carries the subscription URL, because it can bear an access token. Open the profile to see it.",
});


/// Applies a `SettingsSnapshot`. The 0.4.0 preference store holds exactly six
/// renderer-owned fields; everything the 0.3.5 file used to carry now lives in
/// the projected engine configuration and is read, never written, from there.
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
}

function resetPersistedSettingsToSafeState() {
  state.settingsSnapshot = {
    persisted: defaultSettingsSnapshot.persisted,
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
  if (snapshotFields.join("\0") !== ["launch_at_login", "persisted", "settings"].join("\0")) {
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
  if (value.liveStatus === "unknown") {
    const reason = "Start at Login is unavailable because macOS returned an unknown Login Item state.";
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
    const status = value.liveStatus === "not_found" ? "cannot find the signed app" : "reports it is not registered";
    return {
      hint: `The saved preference says On, but macOS ${status}. Switching On retries registration without silently changing the preference.`,
      reason: null,
    };
  }
  return {
    hint: value.liveStatus === "enabled"
      ? "Enabled by macOS and requested by the saved preference."
      : "Disabled by macOS and by the saved preference.",
    reason: null,
  };
}

/// The six renderer-owned preference fields, and nothing else: the preference
/// store rejects an unknown field, and `launch_at_login` may only be changed by
/// the transactional Login Item command, so it is echoed back unchanged.
function persistedSettingsFromUi() {
  const current = state.settingsSnapshot?.settings ?? defaultSettings;
  const theme = document.querySelector("[data-theme-setting]")?.value ?? current.theme ?? "system";
  const fontFamily = document.querySelector("[data-font-family]")?.value ?? current.font_family ?? "";
  return {
    theme: THEME_OPTIONS.some((option) => option.value === theme) ? theme : "system",
    font_family: FONT_OPTIONS.some((option) => option.value === fontFamily) ? fontFamily : "",
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

function applyControllerSnapshot(snapshot) {
  if (!snapshot) return;

  const config = snapshot.config ?? {};
  const mode = config.mode ? config.mode[0].toUpperCase() + config.mode.slice(1).toLowerCase() : null;
  state.mode = ["Global", "Rule", "Direct"].includes(mode) ? mode : null;
  const allowLan = config["allow-lan"] ?? config.allow_lan;
  state.toggles.allowLan = typeof allowLan === "boolean" ? allowLan : false;
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
      return {
        name,
        delay,
        delayFailure: null,
        dead: false,
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

function applyProvidersSnapshot(snapshot) {
  if (!snapshot) return false;
  const proxyProviders = snapshot.proxy_providers ?? [];
  const ruleProviders = snapshot.rule_providers ?? [];
  state.providers = proxyProviders.map((provider) => ({
    name: provider.name,
    type: provider.kind,
    vehicle: provider.vehicle_type,
    updated: provider.updated_at ?? "unknown",
    health: provider.extra?.healthCheck?.lastResult ?? provider.extra?.healthcheck?.lastResult ?? "Unknown",
    proxies: provider.proxies?.length ?? 0,
  }));
  state.ruleProviders = ruleProviders.map((provider) => ({
    name: provider.name,
    type: provider.kind,
    behavior: provider.behavior ?? provider.vehicle_type,
    updated: provider.updated_at ?? "unknown",
    rules: provider.rules?.length ?? 0,
  }));
  state.providerCapabilityError = null;
  return true;
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
        `).join("") || `<p class="empty">No ${state.logFilter === "all" ? "" : `${state.logFilter.toUpperCase()} `}logs for this filter.</p>`;
}

function patchLogStream() {
  const stream = document.querySelector(".log-stream");
  if (!stream) return false;
  const heading = document.querySelector(".logs-layout .toolbar-panel h3");
  if (heading) {
    heading.textContent = `${visibleLogs().length} log entries${state.logsPaused ? " paused" : ""}`;
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

function visibleConnections() {
  const regex = safeRegex(state.connectionSearch);
  const rows = state.connections.filter((connection) => {
    const metadata = connection.metadata ?? {};
    const haystack = [
      connection.host,
      connection.rule,
      ...(connection.chains ?? []),
      metadata.processPath,
      metadata.process_path,
      metadata.sourceIP,
      metadata.source_ip,
      metadata.destinationIP,
      metadata.destination_ip,
      metadata.network,
      metadata.type,
    ].filter(Boolean).join(" ");
    return !state.connectionSearch || (regex ? regex.test(haystack) : haystack.toLowerCase().includes(state.connectionSearch.toLowerCase()));
  });

  const sorters = {
    host: (row) => row.host,
    speed: (row) => row.uploadSpeedBytes + row.downloadSpeedBytes,
    upload: (row) => row.uploadBytes,
    download: (row) => row.downloadBytes,
    age: (row) => Date.parse(row.start || "") || 0,
  };
  const sorter = sorters[state.connectionSort] ?? sorters.age;
  return [...rows].sort((left, right) => {
    const leftValue = sorter(left);
    const rightValue = sorter(right);
    const result = typeof leftValue === "string"
      ? leftValue.localeCompare(String(rightValue))
      : leftValue - rightValue;
    return state.connectionSortDesc ? -result : result;
  }).slice(0, MAX_CONNECTION_ROWS);
}

function visibleRules() {
  const regex = safeRegex(state.ruleSearch);
  return state.rules.filter((rule) => {
    const haystack = [rule.index, rule.type, rule.payload, rule.proxy, rule.hits].filter(Boolean).join(" ");
    return !state.ruleSearch || (regex ? regex.test(haystack) : haystack.toLowerCase().includes(state.ruleSearch.toLowerCase()));
  }).slice(0, 2000);
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
          <b>${escapeHtml(page.title)}</b>
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
  if (phase === "checking") return "Checking for updates…";
  if (update?.error) return `Update failed: ${update.error}`;
  if (update?.available && update?.version) {
    return `Update available: v${update.version}`;
  }
  if (update && update.available === false) {
    return `You’re up to date (v${update.current ?? state.payload?.product?.version ?? "—"})`;
  }
  return "Check GitHub releases for new builds.";
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

/// The migration affordance shown while the fresh-install one-way cutover has
/// not been confirmed. Without it a clean install sits forever on a disabled
/// network with only a reason string.
///
/// The default dashboard cannot run the destructive cutover; it offers the
/// controlled restart into the `--migration-handoff` instance. That instance
/// renders the explicit prepare → confirm flow. No control here mutates the
/// network on its own: prepare only stages and preflights, and confirm requires
/// an explicit checkbox that maps to the backend's `cutover_confirmed` gate.
function renderMigrationBanner() {
  const retirement = state.retirement;
  if (!retirement || typeof retirement.state !== "string") return "";
  const route = migrationRoute(retirement, state.migrationHandoff);
  if (route === "none") return "";
  let cutover = state.cutover;
  if (cutover.receiptId && !cutoverReceiptIsCurrent(cutover)) {
    state.cutover = clearCutoverReceipt(cutover, {
      message: "The cutover preparation expired. Prepare the replacement again.",
    });
    cutover = state.cutover;
  }

  if (route === "unverifiable") {
    return `
      <div class="cfw-migration-banner cfw-migration-unverifiable" role="alert">
        <div class="cfw-migration-copy">
          <strong>Migration state cannot be verified</strong>
          <small>${escapeHtml(retirement.message ?? "The durable legacy-retirement state could not be read. Networking remains fail-closed.")}</small>
        </div>
      </div>
    `;
  }

  if (route === "busy") {
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>Migration is in progress</strong>
          <small>The signed handoff is completing the one-way network transition.</small>
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
      ? "The signed migration session is starting. This dashboard will close only after the new window is ready and replacement networking is safely Off."
      : recovery
        ? "A previous one-way cutover was interrupted. Recovery runs in a separate, signed migration session."
        : profileUnavailable
          ? `Profile state could not be verified: ${profileUnavailable}. Open Profiles and reload it before starting migration.`
          : selectedProfileMissing
            ? "Import and select a replacement profile on Profiles before starting migration. The legacy network remains unchanged until the signed cutover is explicitly confirmed."
            : "This install has not retired the legacy network yet. The network stays disabled until you complete the one-way cutover, which runs in a separate, signed migration session while the old app keeps running.";
    const button = starting
      ? "Starting…"
      : failure
        ? (recovery ? "Retry Recovery…" : "Retry Migration…")
        : (profileUnavailable || selectedProfileMissing)
          ? "Open Profiles"
          : (recovery ? "Open Recovery…" : "Start Migration…");
    const action = profileUnavailable || selectedProfileMissing
      ? "open-migration-profiles"
      : "begin-migration-handoff";
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>${starting ? "Migration session is starting" : recovery ? "Recovery required" : "Finish setup: migrate to the 0.4.0 network"}</strong>
          <small>${escapeHtml(detail)}</small>
          ${retirement.message ? `<small>${escapeHtml(retirement.message)}</small>` : ""}
          ${failure ? `<small>${escapeHtml(failure)}</small>` : ""}
        </div>
        <button type="button" class="cfw-big-button" data-action="${action}" ${starting ? "disabled" : ""}>${button}</button>
      </div>
    `;
  }

  if (route === "recover") {
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>Recover the interrupted cutover</strong>
          <small>${escapeHtml(retirement.message ?? "An interrupted cutover must be recovered before networking is available.")}</small>
          ${cutover.message ? `<small>${escapeHtml(cutover.message)}</small>` : ""}
        </div>
        <button type="button" class="cfw-big-button" data-action="recover-cutover" ${cutover.busy ? "disabled" : ""}>${cutover.busy ? "Recovering…" : "Recover Replacement"}</button>
      </div>
    `;
  }

  const target = cutover.target;
  const targetLabel = target === "tunnel" ? "TUN" : "System Proxy";
  const ready = cutoverReceiptIsCurrent(cutover);
  const step = ready
    ? `
        <label class="cfw-migration-confirm">
          <input type="checkbox" data-cutover-confirm ${cutover.confirmedReceiptId === cutover.receiptId ? "checked" : ""} />
          <span>I understand this one-way cutover retires the legacy network and cannot be undone.</span>
        </label>
        <label class="cfw-migration-confirm">
          <input type="checkbox" data-cutover-dns-review ${cutover.dnsReviewedReceiptId === cutover.receiptId ? "checked" : ""} />
          <span>I have reviewed DNS for every active service in System Settings.</span>
        </label>
        <button type="button" class="cfw-big-button danger" data-action="confirm-cutover" ${cutover.busy ? "disabled" : ""}>${cutover.busy ? "Migrating…" : `Confirm one-way cutover to ${escapeHtml(targetLabel)}`}</button>
      `
    : `
        <button type="button" class="cfw-big-button" data-action="prepare-cutover" ${cutover.busy ? "disabled" : ""}>${cutover.busy ? "Preparing…" : `Prepare cutover to ${escapeHtml(targetLabel)}`}</button>
      `;
  const approvalNote = cutover.awaitingApproval
    ? `<small>System Extension approval is required in System Settings. Approve it, then Prepare again.</small>`
    : "";
  return `
    <div class="cfw-migration-banner" role="status">
      <div class="cfw-migration-copy">
        <strong>Migration session — retire the legacy network</strong>
        <small>The old app keeps running until you confirm. Prepare stages and validates the replacement; nothing on the network changes until you explicitly confirm.</small>
        <label class="cfw-migration-target">
          <span>Replacement</span>
          <select data-cutover-target ${ready || cutover.busy ? "disabled" : ""}>
            <option value="system_proxy" ${target === "system_proxy" ? "selected" : ""}>System Proxy</option>
            <option value="tunnel" ${target === "tunnel" ? "selected" : ""}>TUN</option>
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

function renderGeneral() {
  const product = state.payload.product;
  const appVersion = product.version ?? "—";
  const update = state.updateInfo;
  const updateBadge = update?.available && update?.version
    ? `<button type="button" class="cfw-update-badge" data-action="check-for-updates" title="Update available — click to download">→ v${escapeHtml(String(update.version))}</button>`
    : "";
  const engine = state.engine;
  const projection = state.projection;
  const statusDot = engine.active ? "cfw-status-dot on" : "cfw-status-dot";
  const listenAddress = projection.mixedPort
    ? `${projection.listenAddress ?? "127.0.0.1"}:${projection.mixedPort}`
    : null;
  const bind = projection.listenAddress ?? "unavailable";
  const logLevel = projection.logLevel ?? state.logLevel ?? "info";
  const engineLabel = state.controllerVersion?.version
    ? `sing-box · ${state.controllerVersion.version}`
    : `sing-box · ${engineStateLabel(engine)}`;
  const tunnelCapability = engineToggleCapability("tunMode");
  const proxyCapability = engineToggleCapability("systemProxy");
  const tunnelReason = tunnelCapability.available ? null : tunnelCapability.reason;
  const proxyReason = proxyCapability.available ? null : proxyCapability.reason;
  const tunnelRetryDisabled = state.engineMutationBusy || !tunnelCapability.available ? " disabled" : "";
  const proxyRetryDisabled = state.engineMutationBusy || !proxyCapability.available ? " disabled" : "";
  const launchAtLogin = launchAtLoginPresentation();
  const tunnelRecoveryAction = engine.state === "AwaitingApproval"
    ? `<button class="cfw-text-button" data-action="retry-tun-mode"${tunnelRetryDisabled}>Approve…</button>`
    : engine.state === "Failed" && engine.desiredMode === "tunnel"
      ? `<button class="cfw-text-button" data-action="retry-tun-mode"${tunnelRetryDisabled}>Retry</button>`
      : "";
  const proxyRecoveryAction = engine.state === "Failed" && engine.desiredMode === "system-proxy"
    ? `<button class="cfw-text-button" data-action="retry-system-proxy"${proxyRetryDisabled}>Retry</button>`
    : "";
  const migrationBanner = renderMigrationBanner();
  const projectionError = projection.error ?? "no active profile is selected";
  const projectionNote = projectionError === "no active profile is selected"
    ? "No profile selected"
    : "Projection unreadable";
  return `
    <div class="cfw-general-view">
      <section class="cfw-header">
        <div class="cfw-app-mark">${renderCatLogo()}</div>
        <div class="cfw-title">
          <span>Clash for Mac</span>
          <small>v${escapeHtml(appVersion)}${updateBadge}</small>
        </div>
      </section>

      <section class="cfw-content${migrationBanner ? " cfw-content-migration" : ""}">
        ${migrationBanner}
        ${engine.availabilityReason ? renderRowReason(engine.availabilityReason) : ""}
        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Port</span>
            <span class="general-icons">
              ${generalIconButton("copy-proxy-exports", "terminal", "Copy proxy export commands for Terminal")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${escapeHtml(listenAddress ?? "unavailable")}</span>
            ${renderRowNote(
              listenAddress ? "Fixed by the projection" : projectionNote,
              listenAddress
                ? `The app-owned mixed inbound is projected at ${listenAddress} and is not a user setting in this build.`
                : `The projected configuration could not be read: ${projectionError}`,
            )}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Allow LAN</span>
            <span class="general-icons">
              ${generalIconButton("allow-lan-info", "info", REASONS.allowLan)}
              ${generalIconButton("show-network-interfaces", "device-hub", "network interfaces")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value" title="${escapeHtml(REASONS.bindAddress)}">Bind: ${escapeHtml(bind)}</span>
            ${renderRowNote("Loopback only", `${REASONS.allowLan} ${REASONS.bindAddress}`)}
            ${renderInlineSwitch("allowLan", "Allow LAN", { reason: REASONS.allowLan })}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Log Level</div>
          <div class="cfw-row-right">
            <select class="cfw-select" disabled title="${escapeHtml(REASONS.logLevel)}" aria-label="Engine log level">
              <option value="${escapeHtml(logLevel)}" selected>${escapeHtml(logLevel)}</option>
            </select>
            ${renderRowNote("Pinned by the projection", REASONS.logLevel)}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Engine</span>
            <span class="general-icons">
              ${generalIconButton("preview-runtime-config", "memory", "Preview the projected configuration this engine runs")}
              ${generalIconButton("dns-query", "dns", "Resolve a host through the running engine")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value core-version-link" title="${escapeHtml(projection.controller ? `app-owned controller ${projection.controller}` : "the controller exists only while an engine is running")}">
              <i class="${statusDot}"></i>
              <span>${escapeHtml(engineLabel)}</span>
            </span>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Home Directory</div>
          <div class="cfw-row-right">
            <button class="cfw-text-button" data-action="open-home-directory">Open Folder</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">GeoIP Database</div>
          <div class="cfw-row-right">
            <span class="cfw-link-value" title="${escapeHtml(state.geoipStatus?.path ?? "")}">${escapeHtml(formatGeoipLabel(state.geoipStatus))}</span>
            <button class="cfw-text-button" disabled title="${escapeHtml(REASONS.geoip)}">Update</button>
            ${renderRowNote("Not consumed by this engine", REASONS.geoip)}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>TUN Mode</span>
            <span class="general-icons">
              ${generalIconButton("tun-info", "info", "The Packet Tunnel runs as a signed NetworkExtension System Extension and must be approved once in System Settings.")}
              ${generalIconButton("tun-restore-dns-info", "history", "System DNS after TUN Mode is disabled")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${escapeHtml(tunnelValueLabel(engine))}</span>
            ${tunnelRecoveryAction}
            ${tunnelReason ? renderRowNote("Unavailable", tunnelReason) : ""}
            ${renderInlineSwitch("tunMode", "TUN Mode", {
              reason: tunnelReason,
              disabled: state.engineMutationBusy,
              allowDisableWhenUnavailable: true,
            })}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Mixin</span>
            <span class="general-icons">
              ${generalIconButton("mixin-info", "info", REASONS.mixin)}
            </span>
          </div>
          <div class="cfw-row-right">
            ${renderRowNote("Unavailable", REASONS.mixin)}
            ${renderInlineSwitch("mixin", "Mixin", { reason: REASONS.mixin })}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">System Proxy</div>
          <div class="cfw-row-right">
            ${proxyRecoveryAction}
            ${proxyReason ? renderRowNote("Unavailable", proxyReason) : ""}
            ${renderInlineSwitch("systemProxy", "System Proxy", {
              reason: proxyReason,
              disabled: state.engineMutationBusy,
              allowDisableWhenUnavailable: true,
            })}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Start with macOS</div>
          <div class="cfw-row-right">${renderInlineSwitch("startAtLogin", "Start with macOS", { reason: launchAtLogin.reason, title: launchAtLogin.hint })}</div>
        </div>
      </section>
    </div>
  `;
}

function delayClass(delay, failure = null) {
  if (failure) return "dead";
  if (delay === null || delay === undefined) return "pending";
  if (delay <= 0) return "dead";
  if (delay < 80) return "fast";
  if (delay < 180) return "mid";
  return "slow";
}

function delayLabel(delay, failure = null) {
  if (failure) return delayFailureLabel(failure);
  if (delay === null || delay === undefined) return "Pending";
  if (delay <= 0) return "Probe failed";
  return `${delay} ms`;
}

function delayConcurrency() {
  if (typeof document !== "undefined" && document.hidden) return 2;
  const cores = Number(navigator.hardwareConcurrency) || 8;
  return Math.max(4, Math.min(16, cores));
}

function cancelDelayTest() {
  runtime.delayTestGeneration = (runtime.delayTestGeneration ?? 0) + 1;
  state.toggles.testingDelays = false;
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

function visibleProxyNodeNames() {
  const grid = document.querySelector("[data-proxy-node-grid]");
  if (!grid) return [];
  const viewport = grid.getBoundingClientRect();
  const visible = [];
  grid.querySelectorAll("[data-proxy-node]").forEach((el) => {
    const rect = el.getBoundingClientRect();
    if (rect.bottom >= viewport.top && rect.top <= viewport.bottom) {
      const name = el.getAttribute("data-proxy-node");
      if (name) visible.push(name);
    }
  });
  return visible;
}

function orderNamesVisibleFirst(names) {
  const visible = new Set(visibleProxyNodeNames());
  const head = [];
  const tail = [];
  for (const name of names) {
    if (visible.has(name)) head.push(name);
    else tail.push(name);
  }
  return head.length ? [...head, ...tail] : names;
}

function applyDelayToProxyNodes(name, delay, failure = null) {
  const value = typeof delay === "number" && Number.isFinite(delay) ? delay : null;
  state.proxyGroups.forEach((group) => {
    group.options.forEach((node) => {
      if (node.name === name) {
        node.delay = value;
        node.delayFailure = failure;
        node.dead = Boolean(failure) || (typeof value === "number" && value <= 0);
      }
    });
  });
}

function patchProxyDelayLabels(names) {
  const nameSet = names ? new Set(names) : null;
  document.querySelectorAll("[data-proxy-delay]").forEach((el) => {
    const name = el.getAttribute("data-proxy-delay");
    if (!name || (nameSet && !nameSet.has(name))) return;
    let delay = null;
    let failure = null;
    for (const group of state.proxyGroups) {
      const node = group.options.find((item) => item.name === name);
      if (node) {
        delay = node.delay;
        failure = node.delayFailure;
        break;
      }
    }
    el.className = delayClass(delay, failure);
    el.textContent = delayLabel(delay, failure);
  });
  const tool = document.querySelector('[data-action="delay-test"]');
  if (tool) {
    tool.classList.toggle("active", Boolean(state.toggles.testingDelays));
    tool.disabled = Boolean(state.toggles.testingDelays);
  }
}

function finalizeDelayTestNames(names) {
  names.forEach((name) => {
    let found = null;
    for (const group of state.proxyGroups) {
      const node = group.options.find((item) => item.name === name);
      if (node) {
        found = node;
        break;
      }
    }
    if (found && (found.delay === null || found.delay === undefined) && !found.delayFailure) {
      applyDelayToProxyNodes(name, null, "invalid_response");
    }
  });
  patchProxyDelayLabels(names);
}

function slugDomId(value) {
  return String(value).replace(/[^a-z0-9_-]/gi, "-");
}

function proxyInitial(value) {
  return String(value).trim().slice(0, 2).toUpperCase() || "?";
}

function isManualProxyGroup(type) {
  return ["selector", "relay"].includes(String(type ?? "").toLowerCase());
}

function freshProxyControllerSnapshotAvailable() {
  return state.engine.active
    && state.mode !== null
    && ["controller live", "controller live stream"].includes(state.controllerStatus);
}

/** CFW Proxies section toolbar glyphs (Material-style: travel_explore / report / network_check / visibility). */
function proxyToolIcon(kind) {
  const common = 'width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"';
  switch (kind) {
    case "scroll":
      // travel_explore — globe + magnifier
      return `<svg ${common} fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/><circle cx="18.5" cy="18.5" r="3.2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M20.8 20.8L23 23" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`;
    case "report":
      // report — octagon with !
      return `<svg ${common} fill="currentColor"><path d="M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3s.58-1.3 1.3-1.3 1.3.58 1.3 1.3-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z"/></svg>`;
    case "report-off":
      return `<svg ${common} fill="currentColor"><path d="M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3s.58-1.3 1.3-1.3 1.3.58 1.3 1.3-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z" opacity=".38"/></svg>`;
    case "delay":
      // network_check — signal arcs + needle
      return `<svg ${common} fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12a10 10 0 0 1 20 0"/><path d="M5 12a7 7 0 0 1 14 0"/><path d="M8.5 12a3.5 3.5 0 0 1 7 0"/><path d="M12 12V7.5" stroke-width="2"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/></svg>`;
    case "eye":
      return `<svg ${common} fill="currentColor"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>`;
    case "eye-off":
      return `<svg ${common} fill="currentColor"><path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/></svg>`;
    default:
      return "";
  }
}

function isTimedOutProxy(node) {
  if (!node) return false;
  if (node.dead) return true;
  if (node.delayFailure) return true;
  return typeof node.delay === "number" && node.delay <= 0;
}

function renderProxies() {
  const filter = state.proxyFilter.trim().toLowerCase();
  const groups = state.proxyGroups
    .map((group) => ({
      ...group,
      options: (group.options.length ? group.options : group.observedOption ? [group.observedOption] : []).filter((node) => {
        const matchesFilter = !filter || group.name.toLowerCase().includes(filter) || node.name.toLowerCase().includes(filter);
        const shouldHide = state.toggles.hideUnavailable && isTimedOutProxy(node) && group.now !== node.name;
        return matchesFilter && !shouldHide;
      }),
    }))
    .filter((group) => group.options.length || group.name.toLowerCase().includes(filter));
  const activeGroup = groups.find((group) => group.name === state.activeProxyGroup)
    ?? groups.find((group) => isManualProxyGroup(group.type) && /选择|select|proxy|节点/i.test(group.name))
    ?? groups.find((group) => isManualProxyGroup(group.type) && group.name.toUpperCase() !== "GLOBAL")
    ?? groups.find((group) => isManualProxyGroup(group.type))
    ?? groups[0]
    ?? null;
  const manual = activeGroup ? isManualProxyGroup(activeGroup.type) : false;
  const hideTimedOut = Boolean(state.toggles.hideUnavailable);
  const showProxiesList = state.toggles.showProxiesList !== false;
  const blinkNode = state.proxyBlinkNode;
  const controllerLive = freshProxyControllerSnapshotAvailable();
  const emptyMessage = controllerLive && state.proxyGroups.length === 0
    ? "Active profile has no proxy groups. Switch to a subscription with nodes."
    : "Controller unavailable. No live proxy groups are being displayed.";
  const modeUnavailableTitle = controllerLive
    ? "Switch proxy mode"
    : "Start the engine and wait for a live controller snapshot to switch mode";
  const modeSwitch = `
      <div class="mode-switch proxy-mode-header" role="group" aria-label="Proxy mode">
        ${["Global", "Rule", "Direct"].map((mode) => `
          <button class="${state.mode === mode ? "selected" : ""}" data-mode="${mode}" title="${modeUnavailableTitle}" ${controllerLive ? "" : "disabled"}>${mode} <span>${modeIcon(mode)}</span></button>
        `).join("")}
      </div>`;
  return `
    <div class="proxy-layout">
      ${modeSwitch}

      <div class="cfw-proxy-page">
        ${activeGroup ? `
          <div class="cfw-proxy-head">
            <div class="cfw-proxy-title">
              <span class="proxy-shield">◇</span>
              <h2>${escapeHtml(activeGroup.name)}</h2>
              <span class="proxy-type-badge">${escapeHtml(activeGroup.type?.slice(0, 1) ?? "S")}</span>
              <b>${escapeHtml(activeGroup.now ?? "")}</b>
            </div>
            <div class="cfw-proxy-tools">
              <input class="proxy-filter" data-proxy-filter placeholder="Filter" value="${escapeHtml(state.proxyFilter)}" aria-label="Filter proxies" />
              <button class="proxy-tool" data-action="scroll-to-selected-proxy" title="Scroll to selected proxy">${proxyToolIcon("scroll")}</button>
              <button class="proxy-tool ${hideTimedOut ? "active" : ""}" data-action="toggle-hide-timed-out" title="Show/Hide timed-out proxies">${proxyToolIcon(hideTimedOut ? "report-off" : "report")}</button>
              <button class="proxy-tool ${state.toggles.testingDelays ? "active" : ""}" data-action="delay-test" title="Test latency" ${state.toggles.testingDelays ? "disabled" : ""}>${proxyToolIcon("delay")}</button>
              <button class="proxy-tool ${showProxiesList ? "active" : ""}" data-action="toggle-show-proxies" title="Show/hide proxies">${proxyToolIcon(showProxiesList ? "eye" : "eye-off")}</button>
            </div>
          </div>
          <div class="cfw-proxy-content">
            ${showProxiesList ? `
            <div class="cfw-node-grid" data-proxy-node-grid>
              ${activeGroup.options.map((node) => `
                <button class="cfw-node-card ${activeGroup.now === node.name ? "selected" : ""} ${blinkNode === node.name ? "blink" : ""} ${manual ? "" : "readonly"}" data-proxy-node="${escapeHtml(node.name)}" ${manual ? `data-group="${escapeHtml(activeGroup.name)}" data-node="${escapeHtml(node.name)}"` : "disabled"} title="${manual ? "Select proxy" : "This group type is chosen by the engine, not by the dashboard"}">
                  <i></i>
                  <span>
                    <strong>${nodePrefix(node.name)}${escapeHtml(node.name)}</strong>
                    <small>${escapeHtml(node.kind ?? "Proxy")} ${node.udp === false ? "" : "<em>UDP</em>"}</small>
                  </span>
                  <b class="${delayClass(node.delay, node.delayFailure)}" data-proxy-delay="${escapeHtml(node.name)}">${delayLabel(node.delay, node.delayFailure)}</b>
                </button>
              `).join("")}
            </div>
            ` : `<p class="empty proxy-list-hidden">Proxies hidden — click the eye to show this group’s nodes.</p>`}
            <aside class="cfw-group-rail">
              ${groups.map((group) => `
                <button class="${group.name === activeGroup.name ? "active" : ""}" data-proxy-group-tab="${escapeHtml(group.name)}" title="${escapeHtml(group.name)}">${escapeHtml(groupRailLabel(group.name))}</button>
              `).join("")}
            </aside>
          </div>
        ` : `<p class="empty">${escapeHtml(emptyMessage)}</p>`}
      </div>
    </div>
  `;
}

function modeIcon(mode) {
  return { Global: "↗", Rule: "↝", Direct: "→" }[mode] ?? "";
}

function nodePrefix(name) {
  const value = String(name ?? "");
  if (/[\u{1F1E6}-\u{1F1FF}]/u.test(value)) return "";
  if (/^(DIRECT|REJECT)$/i.test(value)) return "• ";
  return "";
}

function groupRailLabel(name) {
  const value = String(name ?? "").trim();
  if (!value) return "?";
  if (/^GLOBAL$/i.test(value)) return "GLOBAL";
  const withoutFlags = value
    .replace(/[\u{1F1E6}-\u{1F1FF}]/gu, "")
    .replace(/[|｜丨&＆/\\()[\]{}【】「」『』·•._\-:：;；,，。!！?？"'“”‘’]+/g, "")
    .replace(/\s+/g, "");
  const cjk = [...withoutFlags].filter((char) => /[\u4e00-\u9fffA-Za-z0-9]/.test(char)).join("");
  return (cjk || withoutFlags || value).slice(0, 6);
}

function hostFromUrl(value) {
  try {
    return new URL(value).host;
  } catch (_error) {
    return value || "local file";
  }
}

/// CFW profile context-menu items, in the 0.3.5 order and chrome.
///
/// `remoteOnly` items need the profile's subscription URL, which a profile list
/// deliberately never publishes. Opening the menu reads the single profile, so
/// the URL is known here; when that read fails the item is shown disabled with
/// the reason instead of being hidden.
const PROFILE_MENU_ACTIONS = [
  { id: "select", label: "Select", icon: "check", needsInactive: true, needsEngineOff: true },
  { id: "edit", label: "Edit", icon: "edit" },
  { id: "edit-external", label: "Edit externally", icon: "edit" },
  { id: "update", label: "Update", icon: "refresh", remoteOnly: true, needsEngineOff: true },
  { id: "reveal", label: "Show in folder", icon: "folder" },
  { id: "outbounds", label: "Edit outbounds section", icon: "send" },
  { id: "route", label: "Edit route section", icon: "rules" },
  { id: "copy", label: "Copy", icon: "copy", needsEngineOff: true },
  { id: "qrcode", label: "QRCode", icon: "qr", remoteOnly: true },
  { id: "credentials", label: "Credentials", icon: "gear", needsEngineOff: true },
  { id: "settings", label: "Settings", icon: "gear", needsEngineOff: true },
  { id: "delete", label: "Delete", icon: "trash", danger: true, needsEngineOff: true },
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
  state.profileContextMenu = null;
  state.glassDialog = null;
  renderGlassOverlays();
}

/// Profile mutations require the engine to be safely Off, so the dashboard shows
/// the same condition the backend enforces instead of letting a click fail.
function engineIsOff() {
  return state.engine.state === "Off" && state.engine.desiredMode === "off";
}

function engineToggleCapability(key) {
  if (key === "systemProxy") {
    return {
      available: state.engine.systemProxyAvailable === true,
      label: "System Proxy",
      reason: state.engine.availabilityReason
        ?? "The signed ProxyAgent has not reported capability.",
    };
  }
  if (key === "tunMode") {
    return {
      available: state.engine.tunnelAvailable === true,
      label: "TUN Mode",
      reason: state.engine.availabilityReason
        ?? "The signed Packet Tunnel System Extension has not reported capability.",
    };
  }
  return null;
}

/// Enabling a native network mode requires the corresponding verified
/// capability. Disabling an already-requested mode is always admitted so a
/// failed or newly unavailable target never traps the switch On.
function engineToggleChangeAllowed(key, checked, source) {
  const capability = engineToggleCapability(key);
  if (!capability || !checked || capability.available) return true;
  appendLog("info", source, `${capability.label} cannot be enabled: ${capability.reason}`);
  return false;
}

/// Every controller-backed mutation/inspection must use the verified runtime
/// identity, never desired mode. Engine Off is an expected state, so the guard
/// records no warning/error and, most importantly, emits no controller IPC.
function controllerActionAllowed(action, source = "controller") {
  if (source === "provider" && state.engine.providerManagementAvailable !== true) {
    state.providerCapabilityError = PROVIDER_CAPABILITY_UNAVAILABLE;
    appendLog("info", source, `${action} is unavailable: ${PROVIDER_CAPABILITY_UNAVAILABLE}`);
    return false;
  }
  if (state.engine.active) return true;
  state.controllerStatus = "engine off";
  appendLog("info", source, `${action} is unavailable while the engine is Off`);
  return false;
}

/// Runtime projection is an offline operation owned by the selected profile,
/// not by the loopback controller. Repository failure and an actually empty
/// selection remain distinct fail-closed reasons.
function runtimeProjectionActionAllowed(action, source = "profile") {
  if (state.profilesUnavailableReason) {
    appendLog("error", source, `${action} is unavailable because the profile repository could not be read: ${state.profilesUnavailableReason}`);
    return false;
  }
  if (!state.profiles.some((profile) => profile.active === true)) {
    appendLog("info", source, `${action} requires a selected profile`);
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
          ? `controller readback reports ${observed ?? "unavailable"}`
          : "controller readback was unavailable";
        appendLog("error", entry.source, `${entry.failureLabel}: ${errorText(mutationError)}; ${readback}`);
        finishControllerMutationEntry(entry, false);
        continue;
      }
      if (!controllerReadable) {
        appendLog("error", entry.source, `${entry.failureLabel}: controller readback was unavailable`);
        finishControllerMutationEntry(entry, false);
        continue;
      }
      if (!confirmed) {
        appendLog("error", entry.source, `${entry.failureLabel}: controller readback reported ${observed ?? "unavailable"}`);
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
  clearControllerBackedState();
  clearProviderBackedState();
  state.controllerVersion = null;
  state.controllerStatus = active ? "controller loading" : "engine off";
}

function recordProviderOperationFailure(action, error) {
  const message = errorText(error);
  if (message.startsWith(PROVIDER_CAPABILITY_UNSUPPORTED_PREFIX)) {
    state.providerCapabilityError = message;
    appendLog("info", "provider", `${action} is unavailable: ${message}`);
    return;
  }
  appendLog("error", "provider", `${action} failed: ${message}`);
}

/// Reads one profile so the menu knows whether it has a subscription URL.
///
/// A profile list never carries that URL because it can bear an access token;
/// only an explicit single-profile read returns it, which is what opening this
/// menu is.
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
    appendLog("error", "profile", `Could not read ${profile.name} source metadata: ${profile.sourceError}`);
  }
  return profile.sourceUrl;
}

async function openProfileContextMenu(id, clientX, clientY) {
  state.glassDialog = null;
  state.profileContextMenu = { id, x: clientX, y: clientY };
  renderGlassOverlays();
  await resolveProfileSource(id);
  if (state.profileContextMenu?.id === id) renderGlassOverlays();
}

function renderGlassOverlays() {
  const root = document.getElementById("glass-menu-root");
  if (!root) return;

  const parts = [];
  if (state.profileContextMenu) {
    const profile = state.profiles.find((item) => item.id === state.profileContextMenu.id);
    if (profile) {
      const engineOff = engineIsOff();
      const items = PROFILE_MENU_ACTIONS
        .filter((action) => !(action.needsInactive && profile.active))
        .map((action) => {
          let reason = null;
          if (action.remoteOnly) {
            if (profile.sourceUrl === undefined) {
              reason = profile.sourceError
                ? `Subscription URL could not be read: ${profile.sourceError}`
                : "Reading this profile…";
            } else if (profile.sourceUrl === null) {
              reason = "This profile was imported locally and has no subscription URL.";
            }
          }
          if (!reason && action.needsEngineOff && !engineOff) reason = REASONS.engineNotOff;
          return { ...action, reason };
        });
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
            <span>scroll to view more</span>
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
        <div class="glass-dialog" role="dialog" aria-label="Copy profile">
          <h3>Copy profile</h3>
          <label>Name<input data-glass-copy-name value="${escapeHtml(`${profile.name} copy`)}" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-copy-confirm="${escapeHtml(profile.id)}">Copy</button>
          </div>
        </div>
      `);
    } else if (profile && dialog.kind === "settings") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Edit profile information">
          <h3>Edit profile information</h3>
          <label>Name<input data-glass-settings-name value="${escapeHtml(profile.name)}" /></label>
          <label>URL<input data-glass-settings-url value="${escapeHtml(profile.sourceUrl ?? "")}" placeholder="https://..." /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-settings-confirm="${escapeHtml(profile.id)}">Save</button>
          </div>
        </div>
      `);
    } else if (profile && dialog.kind === "delete") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Delete profile">
          <h3>Delete profile</h3>
          <p class="glass-dialog-copy">Are you sure to delete “${escapeHtml(profile.name)}”? This removes the managed profile envelope from the repository.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>No</button>
            <button type="button" class="glass-btn danger" data-glass-delete-confirm="${escapeHtml(profile.id)}">Yes</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "reset-settings") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Reset settings">
          <h3>Reset all settings</h3>
          <p class="glass-dialog-copy">Reset appearance, silent start and update preferences to their defaults? Imported profiles, the selected profile and the Start with macOS registration are all kept.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>No</button>
            <button type="button" class="glass-btn danger" data-glass-reset-confirm>Yes</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "preview-config") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="Projected configuration preview">
          <h3>Projected configuration</h3>
          <p class="glass-dialog-copy">The selected profile projected for the current mode. The app-owned controller secret is redacted.</p>
          <pre class="glass-code">${escapeHtml(dialog.payload ?? "")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            <button type="button" class="glass-btn" data-glass-copy-text>Copy</button>
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
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="Network services">
          <h3>Network services</h3>
          <p class="glass-dialog-copy">Read from SystemConfiguration only. The default-route interface, hardware port and BSD device are not reported: the child-process tools that supplied them are gone.</p>
          <div class="glass-table-wrap"><table class="glass-table"><thead><tr><th>Service</th><th>Order</th><th>Proxy</th></tr></thead><tbody>${rows || '<tr><td colspan="3">No services</td></tr>'}</tbody></table></div>
          ${dialog.unavailable?.length ? `<p class="glass-dialog-copy">Unavailable fields: ${escapeHtml(dialog.unavailable.join(", "))}</p>` : ""}
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button></div>
        </div>
      `);
    } else if (dialog.kind === "dns-query") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="DNS query">
          <h3>Resolve through the running engine</h3>
          <label>Name<input data-glass-dns-name value="${escapeHtml(dialog.payload?.name ?? "www.gstatic.com")}" /></label>
          <label>Type<input data-glass-dns-type value="${escapeHtml(dialog.payload?.type ?? "A")}" /></label>
          <pre class="glass-code">${escapeHtml(dialog.payload?.result ?? "Enter a name and Query.")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            <button type="button" class="glass-btn" data-glass-dns-confirm>Query</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "credentials") {
      const setup = state.credentialSetup;
      const body = !setup
        ? `<p class="glass-dialog-copy">Reading credential requirements…</p>`
        : !setup.vaultAvailable
          ? `<p class="glass-dialog-copy">Credential presence could not be verified, so nothing is being requested and nothing is assumed missing: ${escapeHtml(setup.error ?? "the credential vault is unavailable")}</p>`
          : setup.missing.length === 0
            ? `<p class="glass-dialog-copy">${setup.requiredCount === 0
                ? "This profile references no credentials."
                : `All ${setup.requiredCount} credential reference(s) are already present in the vault.`}</p>`
            : `
              <p class="glass-dialog-copy">${escapeHtml(String(setup.presentCount))} of ${escapeHtml(String(setup.requiredCount))} reference(s) are already present. Enter every missing value once; the batch goes straight to the signed native Keychain vault and is never written to the profile, the log, or the configuration digest.</p>
              ${setup.missing.map((reference, index) => `
                <label>${escapeHtml(credentialLabel(reference.kind))}
                  <input type="password" autocomplete="new-password" data-credential-secret data-credential-index="${index}" aria-label="${escapeHtml(credentialLabel(reference.kind))} secret" />
                </label>
              `).join("")}
            `;
      const canSubmit = Boolean(setup?.vaultAvailable && setup.missing.length && engineIsOff());
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Profile credentials">
          <h3>Credentials${setup?.profileName ? ` · ${escapeHtml(setup.profileName)}` : ""}</h3>
          ${body}
          ${setup?.missing?.length && !engineIsOff() ? `<p class="glass-dialog-copy">${escapeHtml(REASONS.engineNotOff)}</p>` : ""}
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            ${canSubmit ? `<button type="button" class="glass-btn" data-glass-credentials-confirm="${escapeHtml(setup.profileId)}">Store credentials</button>` : ""}
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
        <div class="glass-dialog" role="dialog" aria-label="Credential cleanup">
          <h3>Unused credentials</h3>
          <p class="glass-dialog-copy">${preview
            ? `${escapeHtml(String(preview.orphanCount))} Keychain entr${preview.orphanCount === 1 ? "y is" : "ies are"} not referenced by any stored profile. Cleanup revalidates the repository snapshot and the vault revision before one atomic deletion.`
            : "The credential vault has no unused references."}</p>
          ${references ? `<ul class="glass-list">${references}</ul>` : ""}
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-credential-gc-cancel>Close</button>
            ${preview ? `<button type="button" class="glass-btn danger" data-glass-credential-gc-confirm>Delete unused credentials</button>` : ""}
          </div>
        </div>
      `);
    } else if (dialog.kind === "legacy-profile-migration") {
      const preview = dialog.payload;
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Migrate legacy subscription">
          <h3>Migrate selected legacy subscription</h3>
          <p class="glass-dialog-copy">Convert the ${escapeHtml(formatBytes(preview.legacy_bytes))} legacy YAML snapshot saved on this Mac for “${escapeHtml(preview.name)}”. Migration does not download a newer subscription; ${escapeHtml(preview.source_host)} is retained only as the HTTPS update source. The cached YAML is never executed, and the converted profile and Keychain credentials are validated before selection.</p>
          ${dialog.error ? `<p class="glass-dialog-copy" role="alert">${escapeHtml(dialog.error)}</p>` : ""}
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss ${dialog.busy ? "disabled" : ""}>Cancel</button>
            <button type="button" class="glass-btn" data-glass-legacy-migration-confirm data-preview-id="${escapeHtml(preview.preview_id)}" ${dialog.busy ? "disabled" : ""}>${dialog.busy ? "Migrating…" : "Import and select"}</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "info") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Info">
          <h3>${escapeHtml(dialog.payload?.title ?? "Info")}</h3>
          <p class="glass-dialog-copy">${escapeHtml(dialog.payload?.body ?? "")}</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button></div>
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
          ? `Open Download v${escapeHtml(String(update.version))}`
          : "";
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog product-about" role="dialog" aria-label="About Clash for Mac">
          <div class="product-about-icon">${renderCatLogo()}</div>
          <div class="product-about-name">Clash for Mac</div>
          <div class="product-about-sub">Powered by sing-box</div>
          <div class="product-about-meta">
            <div>版本 ${escapeHtml(String(version))}</div>
            <div>${escapeHtml(String(product.architecture ?? "arm64"))} · macOS ${escapeHtml(String(product.minimum_macos ?? "15.0"))}+</div>
          </div>
          <div class="product-about-status">${escapeHtml(status)}</div>
          ${notes}
          <div class="glass-dialog-actions column">
            ${canOpen ? `<button type="button" class="glass-btn" data-glass-open-update>${primaryLabel}</button>` : ""}
            ${busy && !canOpen ? `<button type="button" class="glass-btn" disabled>${primaryLabel}</button>` : ""}
            <button type="button" class="glass-btn ghost" data-glass-check-update ${busy ? "disabled" : ""}>${phase === "checking" ? "Checking…" : "Check for Update"}</button>
            <button type="button" class="glass-btn ghost" data-glass-dismiss ${busy ? "disabled" : ""}>Close</button>
          </div>
          <div class="product-about-copy">© Clash for Mac · ${escapeHtml(String(product.license ?? "GPL-3.0-or-later"))}</div>
        </div>
      `);
    }
  }

  root.innerHTML = parts.join("");
  positionGlassMenu();
  bindGlassOverlayEvents();
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
        appendLog("error", "profile", `${action} failed: ${errorText(error)}`);
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
        const result = await invoke("import_profile_text", { name, body: text.body });
        await loadProfilesSnapshot();
        closeGlassOverlays();
        appendLog("info", "profile", `Copied profile to ${result.name}; select it to make it active`);
      } catch (error) {
        appendLog("error", "profile", `Copy failed: ${errorText(error)}`);
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
        appendLog("info", "profile", `Profile settings saved: ${name}`);
      } catch (error) {
        appendLog("error", "profile", `Settings failed: ${errorText(error)}`);
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
          deleted ? `Profile deleted: ${profile?.name ?? id}` : `Profile already missing: ${id}`,
        );
      } catch (error) {
        appendLog("error", "profile", `Delete failed: ${errorText(error)}`);
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
        appendLog("warning", "settings", "Preferences reset to defaults");
      } catch (error) {
        appendLog("error", "settings", `Reset failed: ${errorText(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-copy-text]").forEach((button) => {
    button.addEventListener("click", async () => {
      const textValue = state.glassDialog?.payload ?? document.querySelector(".glass-code")?.textContent ?? "";
      try {
        await navigator.clipboard.writeText(String(textValue));
        appendLog("info", "clipboard", "Copied dialog text");
      } catch (error) {
        appendLog("warning", "clipboard", errorText(error));
      }
    });
  });

  document.querySelectorAll("[data-glass-dns-confirm]").forEach((button) => {
    button.addEventListener("click", async () => {
      const name = document.querySelector("[data-glass-dns-name]")?.value?.trim() ?? "";
      const type = document.querySelector("[data-glass-dns-type]")?.value?.trim() || "A";
      if (!controllerActionAllowed("DNS query", "dns")) {
        state.glassDialog = { kind: "dns-query", payload: { name, type, result: "Engine is Off; start the engine before querying DNS." } };
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
        appendLog("error", "dns", `DNS query failed: ${message}`);
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
        await applyActiveProfile(`migrating ${outcome.name}`);
        appendLog(
          "info",
          "migration",
          `${outcome.name} ${outcome.reused ? "recovered" : "imported"}, credentials verified, and selected`,
        );
        state.legacyProfileMigrationPreview = null;
        closeGlassOverlays();
      } catch (error) {
        const message = errorText(error);
        appendLog(
          "error",
          "migration",
          `${committed ? "Migrated profile staging failed" : "Legacy profile migration failed"}: ${message}`,
        );
        state.legacyProfileMigrationPreview = null;
        state.glassDialog = {
          kind: "info",
          payload: committed
            ? {
              title: "Profile migrated; activation failed",
              body: `${message} Reload Profiles and review the selected staged profile; do not resubmit the consumed preview.`,
            }
            : {
              title: "Legacy migration failed",
              body: `${message} The one-shot preview is no longer trusted; preview the legacy profile again before retrying.`,
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
        appendLog("info", "credentials", `Stored ${batch.length} credential reference(s) for ${setup.profileName}`);
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
        appendLog("info", "credentials", `Removed ${receipt.removed_count} unused credential reference(s)`);
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
            ? `Update ${result.version} available`
            : `Already up to date (${result?.current ?? "current"})`,
        );
        openProductAboutDialog({ autoCheck: true, phase: "idle", result });
      } catch (error) {
        appendLog("error", "updater", `Update check failed: ${errorText(error)}`);
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
        appendLog("info", "updater", `Opening the official v${targetVersion} download page…`);
        await invoke("open_available_update", { expectedVersion: targetVersion });
        appendLog("info", "updater", `Official v${targetVersion} download page opened`);
        invalidateUpdateAuthorization();
        closeGlassOverlays();
      } catch (error) {
        appendLog("error", "updater", `Could not open update: ${errorText(error)}`);
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
  if (!profile) throw new Error(`profile not found: ${id}`);

  switch (action) {
    case "select":
      await selectProfileById(id);
      return;
    case "edit":
      await openProfileInspector(id, "edit");
      appendLog("info", "profile", `edit editor opened for ${profile.name}`);
      return;
    case "outbounds":
      await openProfileInspector(id, "edit", "outbounds");
      appendLog("info", "profile", `outbounds section editor opened for ${profile.name}`);
      return;
    case "route":
      await openProfileInspector(id, "edit", "route");
      appendLog("info", "profile", `route section editor opened for ${profile.name}`);
      return;
    case "edit-external":
      await invoke("open_profile_externally", { id });
      appendLog("info", "profile", `Opened ${profile.name} externally`);
      return;
    case "update": {
      const wasActive = profile.active;
      const result = await invoke("update_profile", { id });
      await loadProfilesSnapshot();
      appendLog("info", "profile", `${result.name} subscription updated`);
      if (result.credential_cleanup_pending) {
        appendLog(
          "warning",
          "profile",
          `${result.name} was updated, but credential cleanup is pending: ${result.credential_cleanup_error}`,
        );
      }
      if (wasActive) await applyActiveProfile("profile update");
      return;
    }
    case "reveal":
      await invoke("reveal_profile", { id });
      appendLog("info", "profile", `Show in folder: ${profile.name}`);
      return;
    case "copy":
      state.glassDialog = { kind: "copy", id };
      renderGlassOverlays();
      return;
    case "qrcode":
      await openProfileInspector(id, "qrcode");
      appendLog("info", "profile", `QRCode opened for ${profile.name}`);
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
      throw new Error(`unknown profile menu action: ${action}`);
  }
}

/// Asks the vault which of a profile's immutable credential references are still
/// missing, then opens the entry dialog. Nothing is assumed present or missing
/// when the vault cannot answer.
async function openCredentialSetup(id) {
  const profile = state.profiles.find((item) => item.id === id);
  if (!profile) throw new Error(`profile not found: ${id}`);
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
    appendLog("error", "credentials", `Could not verify credentials for ${profile.name}: ${message}`);
  }
  if (state.glassDialog?.kind === "credentials") renderGlassOverlays();
}

function renderProfiles() {
  const engineOff = engineIsOff();
  const repositoryReason = state.profilesUnavailableReason
    ? `Profile repository unavailable: ${state.profilesUnavailableReason}`
    : null;
  const mutationReason = repositoryReason ?? (engineOff ? null : REASONS.engineNotOff);
  const blocked = mutationReason ? `disabled title="${escapeHtml(mutationReason)}"` : "";
  return `
    <div class="profiles-layout">
      <section class="cfw-profile-remote">
        <div class="cfw-url-box">
          <input data-profile-url placeholder="HTTPS subscription or node link" aria-label="Subscription URL or node link" ${blocked} />
          <button class="paste-icon" data-action="paste-profile-url" title="Paste URL" ${blocked}>▣</button>
        </div>
        <button class="cfw-big-button" data-action="import-profile" ${blocked}>Import Link</button>
        <button class="cfw-big-button" data-action="update-all-profiles" ${blocked}>Update All</button>
        <button class="cfw-big-button" data-action="import-profile-file" ${blocked}>Import File</button>
        <input class="profile-file-hidden" data-profile-file type="file" accept="${PROFILE_SOURCE_ACCEPT}" aria-label="Local JSON, YAML, or node-link profile" ${blocked} />
      </section>

      ${mutationReason ? `<p class="profile-note">${escapeHtml(mutationReason)}</p>` : ""}

      <section class="cfw-profile-list">
        ${repositoryReason ? `
          <div class="empty-profile-state" role="alert">
            <p>${escapeHtml(repositoryReason)}</p>
            <button data-action="reload-dashboard">Reload profile repository</button>
          </div>
        ` : state.profiles.length ? state.profiles.map((profile) => `
          <article class="cfw-profile-card ${profile.active ? "active" : ""}" data-profile-card="${escapeHtml(profile.id)}">
            <i></i>
            <div class="profile-card-main">
              <h3>${escapeHtml(profile.name)}</h3>
              <p>${escapeHtml(profile.active ? "active" : "stored")} (${escapeHtml(profile.updated)})</p>
              <div class="profile-usage">
                <span>${escapeHtml(profile.traffic)}</span>
                <span title="${escapeHtml(REASONS.quota)}">quota not reported</span>
                <span title="${escapeHtml(profile.sourceUrl === undefined ? REASONS.listSource : profile.sourceUrl ?? "imported from a local document")}">${escapeHtml(profileSourceLabel(profile))}</span>
              </div>
            </div>
            <div class="profile-card-primary">
              <button data-profile-action="edit" data-profile-id="${escapeHtml(profile.id)}" title="Open this profile">‹›</button>
            </div>
          </article>
        `).join("") : `
          <div class="empty-profile-state">
            <p>No profiles found in the managed profiles directory.</p>
            <button data-action="migrate-legacy-profiles">Migrate selected legacy subscription</button>
          </div>
        `}
      </section>
      ${renderProfileInspector()}
    </div>
  `;
}

/// A profile list never carries the subscription URL, so the card says so
/// instead of claiming the profile is local.
function profileSourceLabel(profile) {
  if (profile.sourceUrl === undefined) return "source not listed";
  return profile.sourceUrl ? hostFromUrl(profile.sourceUrl) : "local file";
}

function renderProfileInspector() {
  const inspector = state.profileInspector;
  if (!inspector) return "";
  const profile = inspector.profile ?? {};
  const title = `${profile.name ?? inspector.id} · ${inspector.mode}`;
  const sourceUrl = profile.source_url ?? profile.sourceUrl ?? null;
  const engineOff = engineIsOff();
  let body = "";
  if (inspector.mode === "edit") {
    body = `
      <dl class="detail-grid">
        <div><dt>Source URL</dt><dd>${escapeHtml(sourceUrl ?? "local file")}</dd></div>
        <div><dt>Size</dt><dd>${escapeHtml(formatBytes(profile.bytes ?? 0))}</dd></div>
        <div><dt>Active</dt><dd>${profile.active ? "yes" : "no"}</dd></div>
      </dl>
      <textarea class="profile-editor" data-profile-editor spellcheck="false" ${engineOff ? "" : "readonly"}>${escapeHtml(profile.body ?? "")}</textarea>
      <div class="row-actions">
        <button class="button" data-action="save-profile-editor" ${engineOff ? "" : `disabled title="${escapeHtml(REASONS.engineNotOff)}"`}>Save JSON</button>
        ${sourceUrl ? `<button class="button ghost" data-action="update-profile-from-inspector" ${engineOff ? "" : `disabled title="${escapeHtml(REASONS.engineNotOff)}"`}>Update from subscription</button>` : ""}
        <button class="button ghost" data-action="close-profile-inspector">Close</button>
      </div>
      ${engineOff ? "" : `<p class="muted">${escapeHtml(REASONS.engineNotOff)}</p>`}
    `;
  } else if (inspector.mode === "qrcode") {
    body = inspector.svg
      ? `<div class="profile-qr">${inspector.svg}</div><p class="muted">${escapeHtml(sourceUrl ?? "")}</p>`
      : `<p class="empty">${escapeHtml(inspector.error ?? "This local profile has no subscription URL.")}</p>`;
  } else {
    body = `
      <dl class="detail-grid">
        <div><dt>ID</dt><dd>${escapeHtml(profile.id ?? inspector.id)}</dd></div>
        <div><dt>Active</dt><dd>${profile.active ? "yes" : "no"}</dd></div>
        <div><dt>Source URL</dt><dd>${escapeHtml(sourceUrl ?? "local file")}</dd></div>
      </dl>
    `;
  }

  return `
    <section class="panel profile-inspector">
      <div class="section-heading">
        <div>
          <p class="label">Profile Inspector</p>
          <h3>${escapeHtml(title)}</h3>
        </div>
        <button class="button ghost" data-action="close-profile-inspector">Close</button>
      </div>
      ${body}
    </section>
  `;
}

function renderProviders() {
  const updatingAll = state.providerBulkActions.has("update-all-providers");
  const healthAll = state.providerBulkActions.has("health-check-all");
  const engineActive = Boolean(state.engine.active);
  const providerUnavailable = Boolean(state.providerCapabilityError) || !engineActive;
  const providerUnavailableReason = state.providerCapabilityError ?? "Engine is Off; provider management is unavailable.";
  return `
    <div class="providers-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Providers</p>
          <h3>Proxy Providers</h3>
          <p class="muted">${providerUnavailable ? escapeHtml(providerUnavailableReason) : "Live provider capabilities reported by the running engine controller."}</p>
        </div>
        <div class="toolbar-actions">
          <button class="button" data-action="update-all-providers" ${updatingAll || providerUnavailable ? "disabled" : ""}>${updatingAll ? "Updating..." : "Update All"}</button>
          <button class="button ghost" data-action="health-check-all" ${healthAll || providerUnavailable ? "disabled" : ""}>${healthAll ? "Checking..." : "Health Check All"}</button>
          <button class="button ghost" data-action="open-rules">Rules</button>
        </div>
      </section>

      <section class="provider-section">
        <div class="section-title">Proxy Providers</div>
        ${state.providers.length ? state.providers.map((provider) => {
          const updateKey = providerActionKey("proxy-update", provider.name);
          const healthKey = providerActionKey("proxy-health", provider.name);
          const updating = state.providerActions.has(updateKey);
          const checking = state.providerActions.has(healthKey);
          return `
            <article class="panel provider-row">
              <div>
                <p class="label">${escapeHtml(provider.vehicle)}</p>
                <h3>${escapeHtml(provider.name)}</h3>
                <p class="muted">${provider.proxies} proxies · ${escapeHtml(provider.health)} · updated ${escapeHtml(provider.updated)}</p>
              </div>
              <div class="row-actions">
                <button class="button ghost" data-provider-update="${escapeHtml(provider.name)}" ${updating || !engineActive ? "disabled" : ""}>${updating ? "Updating" : "Update"}</button>
                <button class="button" data-provider-health="${escapeHtml(provider.name)}" ${checking || !engineActive ? "disabled" : ""}>${checking ? "Checking" : "Health Check"}</button>
              </div>
            </article>
          `;
        }).join("") : `
          <article class="panel provider-row empty-state">
            <div>
              <p class="label">Controller</p>
              <h3>${providerUnavailable ? "Proxy provider management unavailable" : "No proxy providers loaded"}</h3>
              <p class="muted">${providerUnavailable ? escapeHtml(providerUnavailableReason) : "Driven by the engine controller; no provider rows are invented when the running configuration has none."}</p>
            </div>
          </article>
        `}
      </section>

      <section class="provider-section">
        <div class="section-title">Rule Providers</div>
        ${state.ruleProviders.length ? state.ruleProviders.map((provider) => {
          const updateKey = providerActionKey("rule-update", provider.name);
          const updating = state.providerActions.has(updateKey);
          return `
            <article class="panel provider-row">
              <div>
                <p class="label">${escapeHtml(provider.behavior)}</p>
                <h3>${escapeHtml(provider.name)}</h3>
                <p class="muted">${provider.rules.toLocaleString()} rules · updated ${escapeHtml(provider.updated)}</p>
              </div>
              <div class="row-actions">
                <button class="button ghost" data-rule-provider-update="${escapeHtml(provider.name)}" ${updating || !engineActive ? "disabled" : ""}>${updating ? "Updating" : "Update"}</button>
              </div>
            </article>
          `;
        }).join("") : `
          <article class="panel provider-row empty-state">
            <div>
              <p class="label">Controller</p>
              <h3>${providerUnavailable ? "Rule provider management unavailable" : "No rule providers loaded"}</h3>
              <p class="muted">${providerUnavailable ? escapeHtml(providerUnavailableReason) : "Live from the engine controller; it stays empty when the running configuration has no rule providers."}</p>
            </div>
          </article>
        `}
      </section>
    </div>
  `;
}

function renderLogs() {
  const logs = visibleLogs();
  return `
    <div class="logs-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Diagnostics</p>
          <h3>${logs.length} log entries${state.logsPaused ? " paused" : ""}</h3>
        </div>
        <div class="search-box">
          <input value="${escapeHtml(state.logSearch)}" data-log-search aria-label="Search logs" placeholder="Search logs or regex" />
        </div>
        <div class="segmented" data-log-filters>
          ${["all", "info", "debug", "warning", "error"].map((level) => `
            <button type="button" class="${state.logFilter === level ? "selected" : ""}" data-log-filter="${level}">${level.toUpperCase()}</button>
          `).join("")}
        </div>
        <div class="toolbar-actions">
          <button type="button" class="button ghost" data-action="toggle-log-stream">${state.logsPaused ? "Start" : "Stop"}</button>
          <button type="button" class="button ghost" data-action="copy-logs">Copy</button>
          <button type="button" class="button ghost" data-action="reveal-logs">Open Folder</button>
          <button type="button" class="button ghost" data-action="clear-logs">Clear</button>
        </div>
      </section>

      <section class="panel log-stream">
        ${renderLogStreamHtml()}
      </section>
    </div>
  `;
}

function connectionProcessLabel(connection) {
  const path = connection.metadata?.processPath
    ?? connection.metadata?.process_path
    ?? connection.processPath
    ?? "";
  if (!path) return "—";
  const parts = String(path).split(/[/\\]/).filter(Boolean);
  return parts[parts.length - 1] || String(path);
}

function connectionRowHtml(connection, showProcess) {
  return `
    <article class="cfw-conn-item${showProcess ? " with-process" : ""}" data-connection-id="${escapeHtml(connection.id)}">
      <div class="conn-main">
        <h3>${escapeHtml(connection.host)}</h3>
        <div class="conn-chips">
          <span class="conn1">${escapeHtml(connection.rule || "MATCH")}</span>
          ${(connection.chains ?? []).slice(0, 4).map((chain, index) => `<span class="conn${(index % 6) + 2}">${escapeHtml(chain)}</span>`).join("")}
          <span class="conn7">${escapeHtml(connection.metadata?.network ?? connection.metadata?.type ?? "tcp")}</span>
        </div>
      </div>
      ${showProcess ? `<div class="conn-process" title="${escapeHtml(connection.metadata?.processPath ?? connection.metadata?.process_path ?? "")}">${escapeHtml(connectionProcessLabel(connection))}</div>` : ""}
      <div class="conn-traffic">
        <b data-conn-up>↑ ${escapeHtml(connection.upload)}</b>
        <b data-conn-down>↓ ${escapeHtml(connection.download)}</b>
        <small data-conn-speed>${escapeHtml(connection.speed ?? "0 B/s")}</small>
      </div>
      <div class="conn-actions">
        <button data-connection-detail="${escapeHtml(connection.id)}">Info</button>
        <button data-close-connection="${escapeHtml(connection.id)}" ${state.closingConnectionIds.has(connection.id) ? "disabled" : ""}>${state.closingConnectionIds.has(connection.id) ? "Closing" : "Close"}</button>
      </div>
    </article>
  `;
}

function renderConnections() {
  const connections = visibleConnections();
  const detail = state.connections.find((connection) => connection.id === state.connectionDetailId);
  const totalUp = formatBytes(state.connectionStream.uploadTotal);
  const totalDown = formatBytes(state.connectionStream.downloadTotal);
  const showProcess = state.toggles.showProcess !== false;
  runtime.connectionRowEls = null;
  return `
    <div class="connections-layout" data-connections-root>
      <section class="cfw-conn-header">
        <h1>Connections</h1>
        <div class="cfw-conn-search">
          <span>●</span>
          <input value="${escapeHtml(state.connectionSearch)}" data-connection-search aria-label="Search connections" placeholder="Search connections" />
          ${state.connectionSearch ? '<button data-action="clear-connection-search">×</button>' : ""}
        </div>
        <strong data-conn-totals>Total: ↑ ${totalUp} ↓ ${totalDown}</strong>
      </section>

      <section class="cfw-conn-controls">
        ${[
          ["upload", "↥ ◒"],
          ["download", "↧ ◒"],
          ["upload", "↥ ▥"],
          ["download", "↧ ▥"],
          ["age", "◷"],
          ["host", "▭"],
        ].map(([sort, label]) => `
          <button class="${state.connectionSort === sort ? "selected" : ""}" data-connection-sort="${sort}">${label}</button>
        `).join("")}
        <span></span>
        <button class="danger" data-action="toggle-connection-stream">${state.connectionPaused ? "Resume" : "Pause"}</button>
        <button class="danger" data-action="close-all" data-conn-close-all ${state.closingAllConnections ? "disabled" : ""}>${state.closingAllConnections ? "Closing..." : `Close All (${connections.length})`}</button>
      </section>

      <section class="cfw-conn-scroll" data-conn-scroll>
        ${connections.map((connection) => connectionRowHtml(connection, showProcess)).join("")}
      </section>
      ${detail ? renderConnectionDetail(detail) : ""}
    </div>
  `;
}

function patchConnectionsDom() {
  const root = document.querySelector("[data-connections-root]");
  const scroll = document.querySelector("[data-conn-scroll]");
  if (!root || !scroll || state.activePage !== "connections") {
    renderPage();
    return;
  }

  const connections = visibleConnections();
  const showProcess = state.toggles.showProcess !== false;
  const totals = root.querySelector("[data-conn-totals]");
  if (totals) {
    totals.textContent = `Total: ↑ ${formatBytes(state.connectionStream.uploadTotal)} ↓ ${formatBytes(state.connectionStream.downloadTotal)}`;
  }
  const closeAll = root.querySelector("[data-conn-close-all]");
  if (closeAll) {
    closeAll.disabled = Boolean(state.closingAllConnections);
    closeAll.textContent = state.closingAllConnections
      ? "Closing..."
      : `Close All (${connections.length})`;
  }

  if (!(runtime.connectionRowEls instanceof Map)) {
    runtime.connectionRowEls = new Map();
    scroll.querySelectorAll("[data-connection-id]").forEach((el) => {
      runtime.connectionRowEls.set(el.getAttribute("data-connection-id"), el);
    });
  }

  const nextIds = new Set(connections.map((connection) => connection.id));
  for (const [id, el] of [...runtime.connectionRowEls.entries()]) {
    if (!nextIds.has(id)) {
      el.remove();
      runtime.connectionRowEls.delete(id);
    }
  }

  const fragment = document.createDocumentFragment();
  let appendMode = false;
  connections.forEach((connection, index) => {
    let el = runtime.connectionRowEls.get(connection.id);
    if (!el) {
      const wrap = document.createElement("div");
      wrap.innerHTML = connectionRowHtml(connection, showProcess).trim();
      el = wrap.firstElementChild;
      runtime.connectionRowEls.set(connection.id, el);
      appendMode = true;
      fragment.appendChild(el);
      return;
    }
    const up = el.querySelector("[data-conn-up]");
    const down = el.querySelector("[data-conn-down]");
    const speed = el.querySelector("[data-conn-speed]");
    if (up) up.textContent = `↑ ${connection.upload}`;
    if (down) down.textContent = `↓ ${connection.download}`;
    if (speed) speed.textContent = connection.speed ?? "0 B/s";
    const closeBtn = el.querySelector("[data-close-connection]");
    if (closeBtn) {
      const closing = state.closingConnectionIds.has(connection.id);
      closeBtn.disabled = closing;
      closeBtn.textContent = closing ? "Closing" : "Close";
    }
    const expected = scroll.children[index];
    if (!appendMode && expected !== el) {
      scroll.insertBefore(el, expected ?? null);
    }
  });
  if (fragment.childNodes.length) {
    scroll.appendChild(fragment);
  }

  const detail = state.connections.find((connection) => connection.id === state.connectionDetailId);
  const existingDetail = root.querySelector(".modal-backdrop");
  if (detail && !existingDetail) {
    root.insertAdjacentHTML("beforeend", renderConnectionDetail(detail));
    bindPageEvents();
  } else if (!detail && existingDetail) {
    existingDetail.remove();
  }
}

function scheduleConnectionsPatch() {
  if (runtime.connectionsPatchFrame !== null) return;
  runtime.connectionsPatchFrame = window.requestAnimationFrame(() => {
    runtime.connectionsPatchFrame = null;
    patchConnectionsDom();
  });
}

function connectionFacets(connections) {
  const topEntries = (items) => [...items.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, 6);
  const rules = new Map();
  const chains = new Map();
  connections.forEach((connection) => {
    if (connection.rule) rules.set(connection.rule, (rules.get(connection.rule) ?? 0) + 1);
    (connection.chains ?? []).forEach((chain) => {
      chains.set(chain, (chains.get(chain) ?? 0) + 1);
    });
  });
  return {
    rules: topEntries(rules),
    chains: topEntries(chains),
  };
}

function renderConnectionDetail(connection) {
  const metadata = connection.metadata ?? {};
  const rows = [
    ["Host", connection.host],
    ["Rule", connection.rule],
    ["Chains", (connection.chains ?? []).join(" / ")],
    ["Upload", connection.upload],
    ["Download", connection.download],
    ["Speed", connection.speed],
    ...Object.entries(metadata).filter(([, value]) => value !== null && value !== undefined && value !== ""),
  ];
  return `
    <div class="modal-backdrop" data-action="close-connection-detail">
      <section class="connection-info-modal" data-modal-stop>
        <div class="modal-head">
          <h2>Connection Info</h2>
          <button data-action="close-connection-detail">×</button>
        </div>
        <dl>
          ${rows.map(([key, value]) => `
            <div>
              <dt>${escapeHtml(key)}</dt>
              <dd>${escapeHtml(String(value ?? ""))}</dd>
              <button data-copy-text="${escapeHtml(String(value ?? ""))}">Copy</button>
            </div>
          `).join("")}
        </dl>
      </section>
    </div>
  `;
}

function renderRules() {
  const rules = visibleRules();
  return `
    <div class="rules-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Router</p>
          <h3>${rules.length} / ${state.rules.length} active rule entries</h3>
          <p class="muted">Live data from the engine controller, including rule type, payload, proxy target and hit counters when the engine exposes them.</p>
        </div>
        <div class="search-box">
          <input value="${escapeHtml(state.ruleSearch)}" data-rule-search aria-label="Search rules" placeholder="Search rules" />
        </div>
        <div class="toolbar-actions">
          <button class="button ghost" data-action="reload-rules">Reload Rules</button>
        </div>
      </section>

      <section class="panel table-panel">
        <div class="connection-table">
          <div class="table-row rule-head">
            <span>#</span><span>Type</span><span>Payload</span><span>Proxy</span><span>Hits</span>
          </div>
          ${rules.map((rule) => `
            <div class="table-row rule-row">
              <span>${escapeHtml(rule.index)}</span>
              <span>${escapeHtml(rule.type)}</span>
              <span>${escapeHtml(rule.payload || "-")}</span>
              <span>${escapeHtml(rule.proxy)}</span>
              <span>${escapeHtml(rule.hits)}</span>
            </div>
          `).join("") || '<p class="empty">No rules loaded from the controller.</p>'}
        </div>
      </section>
    </div>
  `;
}

function renderSettingsGroup(title, rows) {
  return `
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Settings</p>
          <h3>${escapeHtml(title)}</h3>
        </div>
      </div>
      <div class="settings-list">${rows.join("")}</div>
    </section>
  `;
}

function renderSettingValue(label, value, hint) {
  return `
    <div class="setting-row">
      <span>
        <b>${escapeHtml(label)}</b>
        <small>${escapeHtml(hint)}</small>
      </span>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `;
}

function renderSettingSelect(label, value, options, hint, dataAttribute, reason = null) {
  return `
    <label class="setting-row setting-control-row ${reason ? "disabled" : ""}">
      <span>
        <b>${escapeHtml(label)}</b>
        <small>${escapeHtml(reason ?? hint)}</small>
      </span>
      <select class="setting-input" ${dataAttribute} ${reason ? `disabled title="${escapeHtml(reason)}"` : ""}>
        ${options.map((option) => `<option value="${escapeHtml(option.value)}" ${option.value === value ? "selected" : ""}>${escapeHtml(option.label)}</option>`).join("")}
      </select>
    </label>
  `;
}

function renderSettingAction(label, value, hint, action, buttonLabel, reason = null) {
  return `
    <div class="setting-row">
      <span>
        <b>${escapeHtml(label)}</b>
        <small>${escapeHtml(reason ?? hint)}</small>
      </span>
      <span class="setting-action">
        <strong>${escapeHtml(value)}</strong>
        <button class="button ghost" data-action="${escapeHtml(action)}" ${reason ? `disabled title="${escapeHtml(reason)}"` : ""}>${escapeHtml(buttonLabel)}</button>
      </span>
    </div>
  `;
}

function renderSettings() {
  const snapshot = state.settingsSnapshot ?? defaultSettingsSnapshot;
  const persisted = snapshot.settings ?? defaultSettings;
  const platform = state.platform;
  const projection = state.projection;
  const engine = state.engine;
  const engineOff = engineIsOff();
  const launchAtLogin = launchAtLoginPresentation();
  const settingsReason = state.settingsUnavailableReason;
  const listenAddress = projection.mixedPort
    ? `${projection.listenAddress ?? "127.0.0.1"}:${projection.mixedPort}`
    : "unavailable";
  return `
    <div class="settings-layout">
      <section class="panel toolbar-panel settings-toolbar">
        <div>
          <p class="label">Preferences</p>
          <h3>${settingsReason ? "Preferences unavailable" : snapshot.persisted ? "cfw-preferences.json loaded" : "Defaults staged"}</h3>
          <p class="muted">${escapeHtml(settingsReason ?? `Appearance, startup and update preferences are the only values this app persists${snapshot.persisted ? "" : "; the file is created on save"}.`)}</p>
        </div>
        <div class="toolbar-actions">
          <button class="button ghost danger" data-action="reset-settings" ${settingsReason ? `disabled title="${escapeHtml(settingsReason)}"` : ""}>Reset All Settings</button>
          <button class="button" data-action="save-settings" ${settingsReason ? `disabled title="${escapeHtml(settingsReason)}"` : ""}>Save Settings</button>
          <button class="button ghost" data-action="reload-settings">Reload From Disk</button>
          <button class="button ghost" data-action="force-quit-app">Force Quit</button>
          <button class="button ghost" data-action="quit-app">Quit</button>
        </div>
      </section>

      ${renderSettingsGroup("General", [
        renderToggle("startAtLogin", "Start at Login", launchAtLogin.hint, { reason: launchAtLogin.reason }),
        renderToggle("silentStart", "Silent Start", "Start hidden in the menu bar without a Dock icon.", { reason: settingsReason }),
        renderToggle("checkForUpdates", "Check for updates", "Check GitHub for a newer official release at launch.", { reason: settingsReason }),
        renderToggle("retainWindowBounds", "Retain window bounds", "Restore the dashboard window position between launches.", { reason: settingsReason }),
        renderSettingAction("Updates", "GitHub Releases", "Check the official release feed now.", "check-for-updates", "Check for Updates"),
      ])}

      ${renderSettingsGroup("Appearance", [
        renderSettingSelect("Theme", persisted.theme ?? "system", THEME_OPTIONS, "Applied immediately and persisted.", "data-theme-setting", settingsReason),
        renderSettingSelect("Font", persisted.font_family ?? "", FONT_OPTIONS, "The preference store accepts these families only.", "data-font-family", settingsReason),
      ])}

      ${renderSettingsGroup("Engine", [
        renderSettingValue("Mixed inbound", listenAddress, projection.error
          ? `The projected configuration could not be read: ${projection.error}`
          : "Projected by the app; not a user setting in this build."),
        renderSettingValue("Controller", projection.controller ?? "not running", "App-owned loopback controller of the running engine. Its secret is never shown."),
        renderSettingValue("Engine state", `${engineStateLabel(engine)} · desired ${engine.desiredMode}`, engine.availabilityReason ?? "Live state of the Authority-mediated engine."),
        renderSettingValue("Log level", projection.logLevel ?? "info", REASONS.logLevel),
        renderToggle("allowLan", "Allow LAN", "", { reason: REASONS.allowLan }),
        renderToggle("mixin", "Mixin", "", { reason: REASONS.mixin }),
      ])}

      ${renderSettingsGroup("Proxies", [
        renderToggle("hideUnavailable", "Hide timed-out proxies", "Hide nodes that failed the latency test. Session only: this build persists no view options."),
        renderSettingValue("Delay test target", "controlled HTTPS", "No delay-test URL preference exists in this build; probes use the fixed HTTPS connectivity target."),
      ])}

      ${renderSettingsGroup("Connections", [
        renderToggle("breakOnProxyChange", "Break connections", "Close open connections after a proxy, mode or profile change. Session only."),
        renderToggle("showProcess", "Show Process", "Show the process name the engine reports for a connection. Session only."),
      ])}

      ${renderSettingsGroup("Credentials", [
        renderSettingValue("Profile credentials", "Keychain vault", "A profile references secrets by immutable id only. Open a profile's context menu → Credentials to store missing values."),
        renderSettingAction(
          "Unused credentials",
          "Vault cleanup",
          "Review Keychain entries that no stored profile references.",
          "preview-credential-gc",
          "Review",
          engineOff ? null : REASONS.engineNotOff,
        ),
      ])}

      ${renderSettingsGroup("Paths", [
        renderSettingAction("Home Directory", "Application Support", "Open the application home directory in Finder.", "open-home-directory", "Open Folder"),
        renderSettingAction("Logs", "logs", "Open the log directory in Finder.", "reveal-logs", "Open Folder"),
      ])}

      ${renderSettingsGroup("DNS", [
        renderSettingAction("System DNS", "never written", REASONS.restoreDns, "tun-restore-dns-info", "Details"),
      ])}

      ${renderSettingsGroup("Cache", [
        renderSettingAction("Fake IP Cache", "Controller-backed", "Flush the engine fake-ip cache.", "flush-fake-ip-cache", "Flush"),
      ])}

      ${platform ? renderSettingsGroup("macOS", [
        renderSettingValue("Minimum macOS", platform.minimum_macos ?? "15.0", "ARM64-only app baseline."),
        renderSettingValue("Intel support", platform.intel_supported ? "Enabled" : "Disabled", "Removed to keep the Apple Silicon runtime lean."),
        renderSettingValue("System proxy", platform.system_proxy_strategy ?? "", "How the system proxy is applied."),
        renderSettingValue("Tunnel", platform.tun_strategy ?? "", "How the packet tunnel runs."),
        renderSettingValue("Helper", platform.helper_strategy ?? "", "Privileged helper strategy."),
        renderSettingValue("launchd", platform.launchd_strategy ?? "", "No product-layer ad-hoc scripts."),
      ]) : renderSettingsGroup("macOS", [
        renderSettingValue("Platform design", "Unavailable", "The platform design could not be read."),
      ])}

      ${renderNetworkDiagnostics()}
    </div>
  `;
}

function renderNetworkDiagnostics() {
  const diagnostics = state.networkDiagnostics;
  if (!diagnostics) {
    return renderSettingsGroup("Network Diagnostics", [
      renderSettingValue("Services", "Unavailable", "macOS network services could not be observed."),
    ]);
  }
  const services = diagnostics.services ?? [];
  const proxied = diagnostics.proxied_services ?? [];
  const unavailable = diagnostics.unavailable ?? [];
  const rows = [
    renderSettingValue(
      "Service order",
      services.length ? `${services.length} service(s)` : "none",
      "Read from SystemConfiguration only; no child process is spawned.",
    ),
    renderSettingValue(
      "Services carrying a proxy",
      proxied.length ? proxied.join(", ") : "none",
      "Any service with a proxy setting enabled, whoever owns it. Ownership is not reported.",
    ),
    ...services.map((service) => renderSettingValue(
      service.display_name ?? service.service_id ?? "unknown",
      serviceProxyLabel(service),
      `set order ${service.order ?? "-"}`,
    )),
  ];
  if (unavailable.length) {
    rows.push(renderSettingValue(
      "Unavailable fields",
      unavailable.join(", "),
      "Reported unavailable by the backend: the child-process tools that produced them are retired.",
    ));
  }
  return renderSettingsGroup("Network Diagnostics", rows);
}

function renderFeedback() {
  const product = state.payload.product;
  const version = product.version ?? "—";
  const update = state.updateInfo;
  const updateLine = update?.available && update?.version
    ? `New version available: v${escapeHtml(String(update.version))} (current v${escapeHtml(String(update.current ?? version))}).`
    : `Current build v${escapeHtml(String(version))} — the menu bar Clash for Mac → Check for Update… also works.`;
  const platform = state.platform;
  return `
    <div class="feedback-layout">
      <section class="panel hero-panel">
        <div>
          <p class="label">About</p>
          <h3>${escapeHtml(product.name ?? "Clash for Mac")} v${escapeHtml(String(version))}${update?.available && update?.version ? ` → v${escapeHtml(String(update.version))}` : ""}</h3>
          <p class="muted">${escapeHtml(product.license ?? "GPL-3.0-or-later")} · ${escapeHtml(product.architecture ?? "arm64")} · macOS ${escapeHtml(product.minimum_macos ?? "15.0")} or later</p>
        </div>
        <span class="badge">ARM64 macOS only</span>
      </section>

      <section class="panel">
        <p class="label">Updates</p>
        <h3>Check for Updates</h3>
        <p class="muted">${updateLine}</p>
        <div class="toolbar-actions">
          <button class="button" data-action="check-for-updates">Check for Updates</button>
        </div>
      </section>

      <section class="panel">
        <p class="label">Architecture</p>
        <h3>How this build runs the network</h3>
        ${platform ? `
          <dl class="ports-list feedback-list">
            <div><dt>system proxy</dt><dd>${escapeHtml(platform.system_proxy_strategy ?? "")}</dd></div>
            <div><dt>tunnel</dt><dd>${escapeHtml(platform.tun_strategy ?? "")}</dd></div>
            <div><dt>helper</dt><dd>${escapeHtml(platform.helper_strategy ?? "")}</dd></div>
            <div><dt>launchd</dt><dd>${escapeHtml(platform.launchd_strategy ?? "")}</dd></div>
          </dl>
        ` : `<p class="muted">Platform design is unavailable.</p>`}
      </section>

      <section class="panel">
        <p class="label">Dashboard</p>
        <h3>Layout reference</h3>
        <dl class="ports-list feedback-list">
          <div><dt>window</dt><dd>850 x 603 minimum baseline</dd></div>
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
  const page = pageById(state.activePage);
  const renderer = pageRenderers[page.id];
  if (typeof renderer !== "function") {
    throw new TypeError(`renderer is unavailable for page ${page.id}`);
  }
  document.title = "";
  const productName = document.getElementById("product-name");
  if (productName) productName.textContent = state.payload.product?.name ?? "Clash for Mac";
  const statusTitle = document.getElementById("status-title");
  if (statusTitle) statusTitle.textContent = state.mode ? `${page.title} - ${state.mode} Mode` : page.title;
  document.getElementById("page-title").textContent = page.title;
  document.getElementById("page-summary").textContent = page.summary;
  const running = state.engine.active;
  const sidebarStatus = document.getElementById("sidebar-status");
  if (sidebarStatus) sidebarStatus.textContent = running ? "Connected" : "Disconnected";
  const sidebarDot = document.getElementById("sidebar-status-dot");
  if (sidebarDot) sidebarDot.className = running ? "on" : "";
  updateStatusBar();

  renderNav();
  document.getElementById("page").innerHTML = renderer();
  bindPageEvents();
  renderGlassOverlays();
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
  if (!controllerActionAllowed(`Proxy mode ${mode}`, "mode")) return;
  if (!freshProxyControllerSnapshotAvailable()) {
    appendLog("info", "mode", `Proxy mode ${mode} requires a fresh controller snapshot`);
    return false;
  }
  const invokeMutation = () => invoke("set_proxy_mode", { mode });
  return enqueueControllerMutation({
    lane: "proxy-mode",
    kind: "mode",
    target: mode,
    source: "mode",
    failureLabel: `Proxy mode ${mode} was not applied`,
    successMessage: `Proxy mode switched to ${mode}`,
    breakConnectionsReason: "mode",
    invokeMutation,
    readObserved: controllerModeFromSnapshot,
    publishObserved: (observed) => { state.mode = observed; },
  });
}

async function applyProxySelection(groupName, proxyName) {
  const group = state.proxyGroups.find((item) => item.name === groupName);
  if (!group) return false;
  if (!freshProxyControllerSnapshotAvailable()) {
    if (!state.engine.active) {
      controllerActionAllowed(`Selecting proxy in ${groupName}`, "proxy");
    } else {
      appendLog("info", "proxy", "Proxy selection requires a fresh controller snapshot");
    }
    return false;
  }
  if (!isManualProxyGroup(group.type)) {
    appendLog("error", "proxy", "The current proxy group is selected by the engine and is read-only");
    return false;
  }
  if (!group.options.some((item) => item.name === proxyName)) {
    appendLog("error", "proxy", "Proxy selection is not an option in the current controller snapshot");
    return false;
  }
  if (!controllerActionAllowed(`Selecting proxy in ${groupName}`, "proxy")) return false;
  const invokeMutation = () => invoke("select_proxy", { group: groupName, proxy: proxyName });
  return enqueueControllerMutation({
    lane: `proxy-selector:${groupName}`,
    kind: "selector",
    groupName,
    target: proxyName,
    source: "proxy",
    failureLabel: `Proxy selection ${groupName} → ${proxyName} was not applied`,
    successMessage: `Proxy group ${groupName} switched to ${proxyName}`,
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
    `${applied.name}: projection ${applied.applied ? "applied and engine restarted" : "validated and staged (engine is off)"} (${formatBytes(applied.bytes ?? 0)})${context ? ` after ${context}` : ""}`,
  );
  await loadRuntimeProjection();
  return applied;
}

async function selectProfileById(id) {
  const profile = state.profiles.find((item) => item.id === id);
  if (!profile) throw new Error(`profile not found: ${id}`);
  if (profile.active) {
    appendLog("info", "profile", `${profile.name} is already active`);
    return false;
  }
  if (!engineIsOff()) throw new Error(REASONS.engineNotOff);
  const previousActiveProfile = state.profiles.find((item) => item.active)?.id ?? null;
  await invoke("select_profile", { id });
  await loadProfilesSnapshot();
  try {
    await applyActiveProfile(`selecting ${profile.name}`);
    return true;
  } catch (error) {
    if (previousActiveProfile) {
      try {
        await invoke("select_profile", { id: previousActiveProfile });
      } catch (rollbackError) {
        appendLog("error", "profile", `Rollback selection failed: ${errorText(rollbackError)}`);
      }
    }
    await loadProfilesSnapshot();
    appendLog("error", "profile", `Could not switch to ${profile.name}: ${errorText(error)}`);
    throw error;
  }
}

function bindPageEvents() {
  document.querySelectorAll("[data-toggle]").forEach((input) => {
    input.addEventListener("change", async (event) => {
      const key = event.currentTarget.dataset.toggle;
      const checked = event.currentTarget.checked;
      try {
        await applyToggle(key, checked, "ui");
      } catch (error) {
        appendLog("error", "ui", `${key} refused: ${errorText(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-theme-setting], [data-font-family]").forEach((input) => {
    input.addEventListener("change", async () => {
      if (state.settingsUnavailableReason) {
        appendLog("warning", "settings", state.settingsUnavailableReason);
        renderPage();
        return;
      }
      try {
        const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
        applyPersistedSettings(snapshot);
        appendLog("info", "settings", "Appearance saved");
      } catch (error) {
        appendLog("error", "settings", `Appearance refused: ${errorText(error)}`);
        try {
          await loadSettingsSnapshot();
        } catch (refreshError) {
          resetPersistedSettingsToSafeState();
          state.settingsUnavailableReason = "Preferences are unavailable because the native settings snapshot could not be verified. Reload from disk before changing them.";
          appendLog("error", "settings", `Appearance recovery failed: ${errorText(refreshError)}`);
        }
      }
      renderPage();
    });
  });

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
        appendLog("info", "profile", `${action} opened for ${id}`);
      } catch (error) {
        appendLog("error", "profile", `${action} failed for ${id}: ${errorText(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-provider-update], [data-rule-provider-update]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const proxyProvider = event.currentTarget.dataset.providerUpdate;
      const ruleProvider = event.currentTarget.dataset.ruleProviderUpdate;
      const name = proxyProvider ?? ruleProvider;
      const actionKey = providerActionKey(proxyProvider ? "proxy-update" : "rule-update", name);
      if (!controllerActionAllowed(`${name} provider update`, "provider")) return;
      const token = captureEngineIdentityToken();
      state.providerActions.add(actionKey);
      renderPage();
      try {
        if (proxyProvider) {
          await invoke("update_proxy_provider", { name: proxyProvider });
        } else {
          await invoke("update_rule_provider", { name: ruleProvider });
        }
        if (!engineIdentityTokenIsCurrent(token)) return;
        await loadProvidersSnapshot(token);
        if (!engineIdentityTokenIsCurrent(token)) return;
        appendLog("info", "provider", `${name} update requested through the engine controller`);
      } catch (error) {
        if (!engineIdentityTokenIsCurrent(token)) return;
        state.controllerStatus = "controller offline";
        recordProviderOperationFailure(`${name} update`, error);
      } finally {
        if (engineIdentityTokenIsCurrent(token)) state.providerActions.delete(actionKey);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-provider-health]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const name = event.currentTarget.dataset.providerHealth;
      const actionKey = providerActionKey("proxy-health", name);
      if (!controllerActionAllowed(`${name} provider health check`, "provider")) return;
      const token = captureEngineIdentityToken();
      state.providerActions.add(actionKey);
      renderPage();
      try {
        await invoke("health_check_proxy_provider", { name });
        if (!engineIdentityTokenIsCurrent(token)) return;
        await loadProvidersSnapshot(token);
        if (!engineIdentityTokenIsCurrent(token)) return;
        appendLog("info", "provider", `${name} health check requested through the engine controller`);
      } catch (error) {
        if (!engineIdentityTokenIsCurrent(token)) return;
        state.controllerStatus = "controller offline";
        recordProviderOperationFailure(`${name} health check`, error);
      } finally {
        if (engineIdentityTokenIsCurrent(token)) state.providerActions.delete(actionKey);
      }
      renderPage();
    });
  });

  const logSearch = document.querySelector("[data-log-search]");
  if (logSearch) {
    logSearch.addEventListener("input", (event) => {
      state.logSearch = event.currentTarget.value;
      patchLogStream();
    });
  }

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

  document.querySelectorAll("[data-connection-detail]").forEach((button) => {
    button.addEventListener("click", (event) => {
      state.connectionDetailId = event.currentTarget.dataset.connectionDetail;
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
        appendLog("info", "clipboard", "Connection field copied");
      } catch (_error) {
        appendLog("warning", "clipboard", "Clipboard API refused copy");
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

  document.querySelectorAll("[data-close-connection]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const id = event.currentTarget.dataset.closeConnection;
      if (!controllerActionAllowed(`Closing connection ${id}`, "connection")) return;
      const token = captureEngineIdentityToken();
      state.closingConnectionIds.add(id);
      renderPage();
      try {
        await invoke("close_connection", { id });
        if (!engineIdentityTokenIsCurrent(token)) return;
        await loadControllerSnapshot(true, token);
        if (!engineIdentityTokenIsCurrent(token)) return;
        appendLog("info", "connection", `Connection ${id} closed`);
      } catch (error) {
        if (!engineIdentityTokenIsCurrent(token)) return;
        state.controllerStatus = "controller offline";
        appendLog("error", "connection", `Controller close failed for ${id}: ${errorText(error)}`);
      } finally {
        if (engineIdentityTokenIsCurrent(token)) state.closingConnectionIds.delete(id);
      }
      renderPage();
    });
  });

}

function bindGlobalEvents() {
  if (runtime.globalEventsBound) return;
  runtime.globalEventsBound = true;

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && (state.profileContextMenu || state.glassDialog)) {
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
      appendLog("info", "shortcut", `Opened ${pageById(state.activePage).title}`);
      renderPage();
      return;
    }
    if (isEditable) return;

    const shortcutAction = {
      g: () => applyProxyMode("Global"),
      r: () => applyProxyMode("Rule"),
      d: () => applyProxyMode("Direct"),
      p: () => applyToggle("systemProxy", !state.toggles.systemProxy, "shortcut"),
      t: () => applyToggle("tunMode", !state.toggles.tunMode, "shortcut"),
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

async function applyToggle(key, checked, source) {
  const isEngineMutation = key === "systemProxy" || key === "tunMode";
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
  state.toggles[key] = checked;
  const engineRequestId = isEngineMutation ? runtime.engineStatusRequestId + 1 : null;
  if (isEngineMutation) {
    runtime.engineStatusRequestId = engineRequestId;
    state.engineMutationBusy = true;
    renderPage();
  }
  try {
    if (key === "systemProxy") {
      const status = await invoke("set_system_proxy_enabled", { enabled: checked });
      if (engineRequestId !== runtime.engineStatusRequestId) return false;
      applyEngineStatus(status);
      await loadNetworkDiagnostics();
      await loadRuntimeProjection();
      if (state.engine.systemProxyActive) await loadControllerSnapshotWithRetry(6, 500);
    } else if (key === "tunMode") {
      const status = await invoke("set_tun_enabled", { enabled: checked });
      if (engineRequestId !== runtime.engineStatusRequestId) return false;
      applyEngineStatus(status);
      await loadRuntimeProjection();
      if (state.engine.tunnelActive) await loadControllerSnapshotWithRetry(12, 500);
    } else if (key === "startAtLogin") {
      const snapshot = await invoke("set_launch_at_login_enabled", { enabled: checked });
      applyPersistedSettings(snapshot);
    } else if (SESSION_TOGGLES.has(key)) {
      appendLog("info", source, `${key} changed to ${checked ? "on" : "off"} for this session`);
      return;
    } else {
      const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
      applyPersistedSettings(snapshot);
    }
    appendLog("info", source, `${key} changed to ${checked ? "on" : "off"}`);
    return true;
  } catch (error) {
    if (isEngineMutation && engineRequestId !== runtime.engineStatusRequestId) return false;
    state.toggles[key] = previous;
    if (key === "startAtLogin") {
      try {
        await loadSettingsSnapshot();
      } catch (refreshError) {
        appendLog("error", "settings", `Could not refresh the Login Item state after refusal: ${errorText(refreshError)}`);
      }
    }
    if (isEngineMutation) {
      try {
        await loadEngineStatus();
      } catch (refreshError) {
        appendLog("error", "engine", `Could not refresh mode state after refusal: ${errorText(refreshError)}`);
      }
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
      appendLog("info", "migration", "Launching the signed migration session…");
      state.cutover.message = "The verified migration window is ready. This dashboard will now close.";
    } catch (error) {
      try {
        await loadBootPayload();
      } catch (refreshError) {
        markHandoffStatusUnverifiable(refreshError);
      }
      appendLog("error", "migration", `Could not start the migration session: ${errorText(error)}`);
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
        state.cutover.message = "Replacement staged and validated. Confirm the one-way cutover to proceed.";
      } else if (preparation.status === "awaiting_approval") {
        state.cutover.awaitingApproval = true;
        state.cutover.message = "System Extension approval is pending.";
      }
    } catch (error) {
      state.cutover = clearCutoverReceipt(state.cutover, {
        targetValue: requestedTarget,
        message: errorText(error),
      });
      appendLog("error", "migration", `Prepare cutover failed: ${errorText(error)}`);
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
        state.cutover = newCutoverState(state.cutover.target, "Cutover complete. Replacement networking is active.");
        appendLog("info", "migration", "Legacy network retired; replacement is active.");
        await loadEngineStatus();
        await loadRetirementStatus();
      } catch (error) {
        state.cutover = clearCutoverReceipt(state.cutover, { message: errorText(error) });
        appendLog("error", "migration", `Cutover failed: ${errorText(error)}`);
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
      state.cutover.message = "Recovery complete.";
      appendLog("info", "migration", "Interrupted cutover recovered.");
      await loadEngineStatus();
      await loadRetirementStatus();
    } catch (error) {
      state.cutover.message = errorText(error);
      appendLog("error", "migration", `Recovery failed: ${errorText(error)}`);
      await loadRetirementStatus();
    } finally {
      state.cutover.busy = false;
    }
  }
  if (action === "scroll-to-selected-proxy") {
    const group = state.proxyGroups.find((item) => item.name === state.activeProxyGroup)
      ?? state.proxyGroups[0];
    const selected = group?.now;
    if (!selected) {
      appendLog("warning", "proxy", "No selected proxy to scroll to");
      return;
    }
    state.toggles.showProxiesList = true;
    state.proxyBlinkNode = selected;
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
  if (action === "toggle-hide-timed-out" || action === "toggle-hide-unavailable") {
    state.toggles.hideUnavailable = !state.toggles.hideUnavailable;
  }
  if (action === "toggle-show-proxies") {
    state.toggles.showProxiesList = !(state.toggles.showProxiesList !== false);
  }
  if (action === "toggle-proxy-filter") {
    state.toggles.showProxyFilter = !state.toggles.showProxyFilter;
    if (!state.toggles.showProxyFilter) state.proxyFilter = "";
  }
  if (action === "break-proxy-connections") {
    if (!controllerActionAllowed("Breaking proxy connections", "proxy")) return;
    const token = captureEngineIdentityToken();
    const count = state.connections.length;
    try {
      await invoke("close_all_connections");
      if (!engineIdentityTokenIsCurrent(token)) return;
      appendLog("warning", "proxy", `Broke ${count} connection(s)`);
      await loadControllerSnapshot(true, token);
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return;
      appendLog("error", "proxy", `Break connections failed: ${errorText(error)}`);
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
    if (!controllerActionAllowed("Closing all connections", "connection")) return;
    const token = captureEngineIdentityToken();
    const count = state.connections.length;
    state.closingAllConnections = true;
    renderPage();
    try {
      await invoke("close_all_connections");
      if (!engineIdentityTokenIsCurrent(token)) return;
      appendLog("warning", "connection", `Closed ${count} active connections`);
      await loadControllerSnapshot(true, token);
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return;
      state.controllerStatus = "controller offline";
      appendLog("error", "connection", `Controller close-all failed; keeping local rows: ${errorText(error)}`);
    } finally {
      if (engineIdentityTokenIsCurrent(token)) state.closingAllConnections = false;
    }
  }
  if (action === "delay-test") {
    if (!controllerActionAllowed("Delay test", "proxy")) return;
    if (state.toggles.testingDelays) {
      cancelDelayTest();
      appendLog("info", "proxy", "Delay test cancelled");
      patchProxyDelayLabels();
      return;
    }
    const activeGroup = state.proxyGroups.find((group) => group.name === state.activeProxyGroup)
      ?? state.proxyGroups.find((group) => isManualProxyGroup(group.type) && group.name.toUpperCase() !== "GLOBAL")
      ?? state.proxyGroups[0]
      ?? null;
    // CFW only latency-tests the current section's `all` list — not every group.
    const names = orderNamesVisibleFirst(
      [...new Set((activeGroup?.options ?? []).map((node) => node.name))]
        .filter((name) => !["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"].includes(String(name).toUpperCase())),
    );
    if (!names.length) {
      appendLog("warning", "proxy", "No proxy nodes available for delay test");
    } else {
      const generation = (runtime.delayTestGeneration = (runtime.delayTestGeneration ?? 0) + 1);
      state.toggles.testingDelays = true;
      if (activeGroup) {
        activeGroup.options.forEach((node) => {
          if (names.includes(node.name)) {
            node.delay = null;
            node.delayFailure = null;
            node.dead = false;
          }
        });
      }
      patchProxyDelayLabels(names);
      try {
        // No delay-test URL preference exists in 0.4.0; the command supplies
        // the pinned engine's fixed HTTPS connectivity target.
        const delayByName = new Map();
        const failureByName = new Map();
        let offset = 0;
        while (offset < names.length) {
          if (generation !== runtime.delayTestGeneration) break;
          const concurrency = delayConcurrency();
          const chunk = names.slice(offset, offset + concurrency);
          offset += chunk.length;
          const results = await invoke("test_proxy_delays", {
            proxies: chunk,
            timeoutMs: 5000,
            concurrency,
          });
          if (generation !== runtime.delayTestGeneration) break;
          const seen = new Set();
          for (const item of results ?? []) {
            seen.add(item.name);
            if (Number.isFinite(item.delay) && item.delay > 0) {
              delayByName.set(item.name, item.delay);
              applyDelayToProxyNodes(item.name, item.delay);
            } else {
              const failure = item.error_kind ?? "invalid_response";
              failureByName.set(item.name, failure);
              applyDelayToProxyNodes(item.name, null, failure);
            }
          }
          for (const name of chunk) {
            if (!seen.has(name) && !delayByName.has(name) && !failureByName.has(name)) {
              failureByName.set(name, "invalid_response");
              applyDelayToProxyNodes(name, null, "invalid_response");
            }
          }
          patchProxyDelayLabels(chunk);
        }
        if (generation === runtime.delayTestGeneration) {
          finalizeDelayTestNames(names);
          const failed = failureByName.size
            + names.filter((name) => !delayByName.has(name) && !failureByName.has(name)).length;
          const ok = delayByName.size;
          const failures = new Map();
          for (const kind of failureByName.values()) {
            failures.set(kind, (failures.get(kind) ?? 0) + 1);
          }
          const failureSummary = [...failures.entries()]
            .map(([kind, count]) => `${count} ${delayFailureLabel(kind).toLowerCase()}`)
            .join(", ");
          appendLog(
            failed ? "error" : "info",
            "proxy",
            `Delay test (${activeGroup?.name ?? "group"}): ${ok} ok${failed ? `, ${failed} failed${failureSummary ? ` (${failureSummary})` : ""}` : ""} · concurrency ${delayConcurrency()}`,
          );
        }
      } catch (error) {
        if ((runtime.delayTestGeneration ?? 0) === generation) {
          finalizeDelayTestNames(names);
          appendLog("error", "proxy", `Delay test failed: ${errorText(error)}`);
        }
      } finally {
        if ((runtime.delayTestGeneration ?? 0) === generation) {
          state.toggles.testingDelays = false;
          patchProxyDelayLabels(names);
        }
      }
    }
  }
  if (action === "reload-proxies") {
    if (!controllerActionAllowed("Reloading proxies", "proxy")) return;
    const live = await loadControllerSnapshot();
    appendLog(live ? "info" : "error", "proxy", live ? "Controller snapshot reloaded" : "Controller unavailable; keeping local data");
  }
  if (action === "copy-proxy-exports") {
    const port = state.projection.mixedPort;
    if (!port) {
      appendLog("warning", "shell", `The projected inbound port is unavailable: ${state.projection.error ?? "no active profile is selected"}`);
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
      appendLog("info", "shell", "Copied proxy export commands for Terminal");
    } catch (error) {
      appendLog("warning", "clipboard", errorText(error));
    }
  }
  if (action === "allow-lan-info") {
    state.glassDialog = {
      kind: "info",
      payload: {
        title: "Allow LAN",
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
    if (!runtimeProjectionActionAllowed("Configuration preview")) return;
    try {
      const body = await invoke("read_runtime_config_text");
      state.glassDialog = { kind: "preview-config", payload: body };
      renderGlassOverlays();
      return;
    } catch (error) {
      appendLog("error", "engine", `Configuration preview failed: ${errorText(error)}`);
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
        title: "TUN Mode",
        body: "TUN Mode runs the packet tunnel as a signed NetworkExtension System Extension. macOS asks for approval once, under System Settings › General › Login Items & Extensions; until it is approved the switch stays unavailable.",
      },
    };
    renderGlassOverlays();
    return;
  }
  if (action === "mixin-info") {
    state.glassDialog = {
      kind: "info",
      payload: {
        title: "Mixin",
        body: REASONS.mixin,
      },
    };
    renderGlassOverlays();
    return;
  }
  if (action === "open-home-directory") {
    try {
      await invoke("reveal_home_directory");
      appendLog("info", "shell", "Home Directory opened in Finder");
    } catch (error) {
      appendLog("error", "shell", `Open Folder failed: ${errorText(error)}`);
    }
  }
  if (action === "retry-system-proxy") {
    await applyToggle("systemProxy", true, "explicit retry");
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
        appendLog("info", "shell", "Opened System Settings › General › Login Items & Extensions");
      }
    } catch (error) {
      appendLog("error", "engine", `TUN retry failed: ${errorText(error)}`);
    }
    renderPage();
  }
  if (action === "tun-restore-dns-info") {
    state.glassDialog = {
      kind: "info",
      payload: { title: "System DNS", body: REASONS.restoreDns },
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
      appendLog("warning", "profile", "No profile is open");
    } else {
      await runProfileMenuAction("update", id);
      await openProfileInspector(id, "edit");
    }
  }
  if (action === "import-profile") {
    const input = document.querySelector("[data-profile-url]");
    const url = input?.value?.trim();
    if (!url) {
      appendLog("warning", "profile", "A subscription URL or node link is required before import");
    } else if (!engineIsOff()) {
      appendLog("warning", "profile", REASONS.engineNotOff);
    } else {
      const subscription = isSubscriptionSource(url);
      const result = subscription
        ? await invoke("import_profile_url", { url, name: null, activate: true })
        : await invoke("import_profile_text", { name: null, body: url });
      input.value = "";
      await loadProfilesSnapshot();
      appendLog("info", "profile", `Profile imported: ${result.name} (${formatBytes(result.bytes ?? 0)})`);
      if (subscription) {
        await applyActiveProfile(`importing ${result.name}`);
      } else {
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
      appendLog("info", "profile", "Profile URL pasted from clipboard");
    } catch (_error) {
      appendLog("warning", "profile", "Clipboard read was refused");
    }
  }
  if (action === "import-profile-file") {
    const input = document.querySelector("[data-profile-file]");
    const file = input?.files?.[0];
    if (!file) {
      input?.click();
      return;
    }
    if (!engineIsOff()) {
      appendLog("warning", "profile", REASONS.engineNotOff);
      input.value = "";
      renderPage();
      return;
    }
    try {
      const body = await readProfileSourceFile(file);
      const result = await invoke("import_profile_text", { name: file.name, body });
      await loadProfilesSnapshot();
      appendLog("info", "profile", `Local profile imported: ${result.name} (${formatBytes(result.bytes ?? 0)})`);
      await selectProfileById(result.id);
      await openCredentialSetup(result.id);
    } finally {
      input.value = "";
    }
  }
  if (action === "migrate-legacy-profiles") {
    if (state.profilesUnavailableReason) {
      appendLog("error", "profile", `Profile repository is unavailable: ${state.profilesUnavailableReason}`);
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
          payload: { title: "Legacy profile is local", body: preview.reason },
        };
      } else {
        state.glassDialog = {
          kind: "info",
          payload: { title: "No selected legacy subscription", body: "The legacy settings file does not select a profile that can be migrated." },
        };
      }
      renderGlassOverlays();
      return;
    } catch (error) {
      const message = errorText(error);
      appendLog("error", "migration", `Legacy profile preview failed: ${message}`);
      state.glassDialog = { kind: "info", payload: { title: "Legacy migration failed", body: message } };
      renderGlassOverlays();
      return;
    }
  }
  if (action === "update-all-profiles") {
    if (!engineIsOff()) {
      appendLog("warning", "profile", REASONS.engineNotOff);
      renderPage();
      return;
    }
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
        const result = await invoke("update_profile", { id: profile.id });
        updated += 1;
        if (result.credential_cleanup_pending) {
          cleanupPending += 1;
          appendLog(
            "warning",
            "profile",
            `${profile.name} was updated, but credential cleanup is pending: ${result.credential_cleanup_error}`,
          );
        }
      } catch (error) {
        failed += 1;
        appendLog("error", "profile", `Update failed for ${profile.name}: ${errorText(error)}`);
      }
    }
    await loadProfilesSnapshot();
    if (updated && activeProfile().active) {
      try {
        await applyActiveProfile("Update All");
      } catch (error) {
        appendLog("error", "profile", `Active profile reapply failed: ${errorText(error)}`);
      }
    }
    appendLog(
      failed ? "error" : "info",
      "profile",
      `Update All completed: ${updated} updated${failed ? `, ${failed} failed` : ""}${cleanupPending ? `, ${cleanupPending} cleanup pending` : ""}${local ? `, ${local} without a subscription URL` : ""}`,
    );
  }
  if (action === "save-profile-editor") {
    const editor = document.querySelector("[data-profile-editor]");
    const inspector = state.profileInspector;
    if (!editor || !inspector?.profile?.id) {
      appendLog("warning", "profile", "No profile editor is open");
    } else {
      const result = await invoke("save_profile_text", { id: inspector.profile.id, body: editor.value });
      await loadProfilesSnapshot();
      appendLog("info", "profile", `Profile JSON saved: ${formatBytes(result.bytes ?? 0)}`);
      if (result.active) await applyActiveProfile("editing the profile");
      await openProfileInspector(result.id, "edit");
      await openCredentialSetup(result.id);
    }
  }
  if (action === "close-profile-inspector") {
    state.profileInspector = null;
  }
  if (action === "update-all-providers") {
    if (!controllerActionAllowed("Update All", "provider")) return;
    const token = captureEngineIdentityToken();
    state.providerBulkActions.add(action);
    renderPage();
    try {
      const [proxyOutcome, ruleOutcome] = await Promise.allSettled([
        invoke("update_all_proxy_providers"),
        invoke("update_all_rule_providers"),
      ]);
      if (!engineIdentityTokenIsCurrent(token)) return;
      if (proxyOutcome.status === "rejected") recordProviderOperationFailure("Proxy provider update", proxyOutcome.reason);
      if (ruleOutcome.status === "rejected") recordProviderOperationFailure("Rule provider update", ruleOutcome.reason);
      await loadProvidersSnapshot(token);
      if (!engineIdentityTokenIsCurrent(token)) return;
      if (proxyOutcome.status === "fulfilled" && ruleOutcome.status === "fulfilled") {
        const proxySummary = providerBatchSummary("Proxy providers", proxyOutcome.value);
        const ruleSummary = providerBatchSummary("Rule providers", ruleOutcome.value);
        const level = providerBatchSucceeded(proxyOutcome.value) && providerBatchSucceeded(ruleOutcome.value) ? "info" : "error";
        appendLog(level, "provider", `Update All completed · ${proxySummary} · ${ruleSummary}`);
      } else {
        appendLog("info", "provider", "Update All did not complete; see the provider result above");
      }
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return;
      state.controllerStatus = "controller offline";
      recordProviderOperationFailure("Update All", error);
    } finally {
      if (engineIdentityTokenIsCurrent(token)) {
        state.providerBulkActions.delete(action);
        renderPage();
      }
    }
  }
  if (action === "health-check-all") {
    if (!controllerActionAllowed("Health Check All", "provider")) return;
    const token = captureEngineIdentityToken();
    state.providerBulkActions.add(action);
    renderPage();
    try {
      const proxyProviders = await invoke("health_check_all_proxy_providers");
      if (!engineIdentityTokenIsCurrent(token)) return;
      await loadProvidersSnapshot(token);
      if (!engineIdentityTokenIsCurrent(token)) return;
      appendLog(providerBatchSucceeded(proxyProviders) ? "info" : "error", "provider", providerBatchSummary("Health Check All", proxyProviders));
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return;
      state.controllerStatus = "controller offline";
      recordProviderOperationFailure("Health Check All", error);
    } finally {
      if (engineIdentityTokenIsCurrent(token)) {
        state.providerBulkActions.delete(action);
        renderPage();
      }
    }
  }
  if (action === "flush-fake-ip-cache") {
    if (!controllerActionAllowed("Fake IP cache flush", "cache")) return;
    const token = captureEngineIdentityToken();
    try {
      await invoke("flush_fake_ip_cache");
      if (!engineIdentityTokenIsCurrent(token)) return;
      appendLog("info", "cache", "Fake IP cache flushed through the engine controller");
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return;
      state.controllerStatus = "controller offline";
      appendLog("error", "cache", `Fake IP cache flush failed: ${errorText(error)}`);
    }
  }
  if (action === "reload-rules") {
    if (!controllerActionAllowed("Rules reload", "rules")) return;
    const loaded = await loadRulesSnapshot();
    appendLog(loaded ? "info" : "error", "rules", loaded ? `Loaded ${state.rules.length} controller rules` : "Rules controller endpoint unavailable");
  }
  if (action === "toggle-log-stream") {
    const pause = !state.logsPaused;
    if (!pause && !controllerActionAllowed("Starting request logs", "logs")) return;
    const previous = state.logsPaused;
    state.logsPaused = pause;
    try {
      const changed = await setLogStreamRunning(!pause);
      if (!changed) return;
      appendLog("info", "logs", `Request logs ${pause ? "stopped" : "started"}`);
    } catch (error) {
      if (!pause) state.logsPaused = previous;
      appendLog("error", "logs", `Log stream change failed: ${errorText(error)}`);
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
      appendLog("info", "logs", `Copied ${state.logs.length} log line(s) to clipboard`);
    } catch (error) {
      appendLog("warning", "logs", `Copy logs refused: ${errorText(error)}`);
    }
  }
  if (action === "reveal-logs") {
    try {
      await invoke("reveal_logs_directory");
      appendLog("info", "logs", "Logs folder opened in Finder");
    } catch (error) {
      appendLog("error", "logs", `Open Folder failed: ${errorText(error)}`);
    }
  }
  if (action === "toggle-connection-stream") {
    const pause = !state.connectionPaused;
    if (!pause && !controllerActionAllowed("Starting connection stream", "connections")) return;
    const previous = state.connectionPaused;
    state.connectionPaused = pause;
    try {
      const changed = await setConnectionsStreamRunning(!pause);
      if (!changed) return;
      appendLog("info", "connections", `Connection stream ${pause ? "stopped" : "started"}`);
    } catch (error) {
      if (!pause) state.connectionPaused = previous;
      appendLog("error", "connections", `Connection stream change failed: ${errorText(error)}`);
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
    appendLog("info", "settings", "Preferences saved");
  }
  if (action === "check-for-updates") {
    try {
      openProductAboutDialog({ autoCheck: true, phase: "checking" });
      const result = await invoke("check_for_updates");
      await promptAvailableUpdate(result);
    } catch (error) {
      appendLog("error", "updater", `Update check failed: ${errorText(error)}`);
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
    appendLog("info", "settings", "Preferences reloaded from disk");
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
    appendLog("warning", "connection", `Closed ${count} connection(s) after ${reason} switch`);
    return true;
  } catch (error) {
    if (!engineIdentityTokenIsCurrent(token) || !publishAllowed()) return false;
    state.controllerStatus = "controller offline";
    appendLog("error", "connection", `Connection cleanup after ${reason} switch failed: ${errorText(error)}`);
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
      appendLog("error", "profile", `Could not render the profile QR code: ${inspector.error}`);
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
  state.lastRefresh = "Just now";
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
    await loadProvidersSnapshot();
    if (state.activePage === "rules") await loadRulesSnapshot();
  }
  appendLog("info", "shell", "Dashboard reloaded");
  renderPage();
}

function applyBootPayload(payload) {
  const normalized = normalizeBootPayload(payload);
  state.payload = { product: normalized.product };
  state.migrationHandoff = normalized.migration_handoff;
  state.migrationHandoffStatus = normalized.migration_handoff_status;
  migrationHandoffRendererReady = normalized.migration_handoff_renderer_ready;
}

function markHandoffStatusUnverifiable(error) {
  state.migrationHandoffStatus = {
    state: "failed",
    code: "migration_handoff_task_failed",
    message: "Migration handoff status could not be verified. Review the application log before retrying.",
  };
  appendLog("error", "migration", `Migration handoff state could not be trusted: ${errorText(error)}`);
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
    appendLog("error", "engine", `Engine state could not be trusted: ${errorText(error)}`);
  }
  state.engine = next;
  if (engineRuntimeIdentityChanged(previous, next)) {
    invalidateEngineBoundState(next.active);
  } else if (!next.active) {
    // Off is an expected steady state. Repeated snapshots still clear any
    // event/request result that arrived between native status reads.
    clearControllerBackedState();
    clearProviderBackedState();
    state.controllerVersion = null;
    state.controllerStatus = "engine off";
  }
  // Switches express the user's desired mode. Runtime readiness remains a
  // separate label/status dot; pending and failed requests stay switchable Off
  // while the adjacent action provides an explicit, state-bound retry.
  state.toggles.systemProxy = state.engine.desiredMode === "system-proxy";
  state.toggles.tunMode = state.engine.desiredMode === "tunnel";
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
    appendLog("error", "engine", `Unable to read the engine state: ${errorText(error)}`);
  }
  try {
    state.geoipStatus = await invoke("geoip_database_status");
  } catch (error) {
    state.geoipStatus = null;
    appendLog("error", "geoip", `Unable to read the GeoIP database status: ${errorText(error)}`);
  }
  if (state.engine.active) {
    const token = captureEngineIdentityToken();
    try {
      const version = await invoke("controller_version");
      if (engineIdentityTokenIsCurrent(token)) state.controllerVersion = version;
    } catch (error) {
      if (!engineIdentityTokenIsCurrent(token)) return false;
      state.controllerVersion = null;
      appendLog("error", "controller", `Unable to read the controller version: ${errorText(error)}`);
    }
  } else {
    state.controllerVersion = null;
  }
  return true;
}

/// Reads the legacy-retirement state machine so the dashboard can surface the
/// fresh-install AwaitingConfirmation lock and offer the migration path. A read
/// or schema failure becomes an explicit fail-closed `unverifiable` state.
async function loadRetirementStatus() {
  try {
    state.retirement = normalizeRetirementStatus(await invoke("legacy_retirement_status"));
  } catch (error) {
    state.retirement = unverifiableRetirementStatus(errorText(error));
    appendLog("error", "engine", `Unable to read the legacy retirement state: ${errorText(error)}`);
  }
}

async function loadPlatformDesign() {
  try {
    state.platform = await invoke("current_platform_design");
  } catch (error) {
    state.platform = null;
    appendLog("error", "shell", `Unable to read the platform design: ${errorText(error)}`);
  }
}

/// Reads the projected engine configuration so the dashboard can show the real
/// inbound and controller endpoint instead of a remembered preference. Without a
/// selected profile there is no projection, which is reported, not invented.
async function loadRuntimeProjection() {
  if (state.profilesUnavailableReason) {
    state.projection = {
      mixedPort: null,
      listenAddress: null,
      controller: null,
      logLevel: null,
      error: `profile state is unavailable: ${state.profilesUnavailableReason}`,
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
    const inbound = (document.inbounds ?? []).find((entry) => entry?.type === "mixed");
    state.projection = {
      mixedPort: Number.isInteger(inbound?.listen_port) ? inbound.listen_port : null,
      listenAddress: typeof inbound?.listen === "string" ? inbound.listen : null,
      controller: document.experimental?.clash_api?.external_controller ?? null,
      logLevel: document.log?.level ?? null,
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
    appendLog("error", "profile", `Active profile projection could not be read: ${state.projection.error}`);
    return false;
  }
}

async function loadSettingsSnapshot() {
  const snapshot = await invoke("read_settings_snapshot");
  applyPersistedSettings(snapshot);
}

async function loadNetworkDiagnostics() {
  try {
    state.networkDiagnostics = await invoke("network_diagnostics");
  } catch (error) {
    state.networkDiagnostics = null;
    appendLog("error", "network", `Unable to inspect macOS network services: ${errorText(error)}`);
  }
}

function resetControllerStateForInactiveEngine() {
  clearControllerBackedState();
  clearProviderBackedState();
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
      if (reportFailure) appendLog("error", "controller", "Running engine returned no controller snapshot");
      return false;
    }
    if (observe) observe(snapshot);
    applyControllerSnapshot(snapshot);
    applyPendingControllerIntents();
    invoke("refresh_tray_menu").catch((error) => {
      if (engineIdentityTokenIsCurrent(token) && publishAllowed()) {
        appendLog("error", "tray", `Tray refresh failed: ${errorText(error)}`);
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

function clearProviderBackedState() {
  state.providers = [];
  state.ruleProviders = [];
  state.providerCapabilityError = null;
  state.providerActions.clear();
  state.providerBulkActions.clear();
}

async function loadProvidersSnapshot(token = captureEngineIdentityToken()) {
  if (state.engine.providerManagementAvailable !== true) {
    clearProviderBackedState();
    state.providerCapabilityError = PROVIDER_CAPABILITY_UNAVAILABLE;
    return false;
  }
  if (!engineIdentityTokenIsCurrent(token)) {
    if (!state.engine.active) clearProviderBackedState();
    return false;
  }
  try {
    const snapshot = await invoke("providers_snapshot");
    if (!engineIdentityTokenIsCurrent(token)) return false;
    if (!applyProvidersSnapshot(snapshot)) return false;
    return true;
  } catch (error) {
    if (!engineIdentityTokenIsCurrent(token)) return false;
    clearProviderBackedState();
    state.providerCapabilityError = errorText(error);
    if (!state.providerCapabilityError.startsWith(PROVIDER_CAPABILITY_UNSUPPORTED_PREFIX)) {
      appendLog("error", "provider", state.providerCapabilityError);
    }
    return false;
  }
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

async function loadProfilesSnapshot() {
  try {
    const profiles = await invoke("profiles_snapshot");
    if (!Array.isArray(profiles)) throw new TypeError("profile snapshot is not an array");
    const known = new Map(state.profiles.map((profile) => [profile.id, profile]));
    state.profiles = profiles.map((profile) => ({
      id: profile.id,
      name: profile.name,
      updated: profile.updated_epoch_secs
        ? formatRelativeUpdated(profile.updated_epoch_secs)
        : "unknown",
      updatedEpochSecs: profile.updated_epoch_secs ?? null,
      traffic: formatBytes(profile.bytes ?? 0),
      active: Boolean(profile.active),
      // A profile list carries no subscription URL, because it can bear an
      // access token. `undefined` means "not published in a list"; it is
      // resolved by an explicit single-profile read.
      sourceUrl: known.get(profile.id)?.sourceUrl,
      sourceError: known.get(profile.id)?.sourceError ?? null,
    }));
    state.profilesUnavailableReason = null;
    if (state.credentialSetup && !state.profiles.some(({ id }) => id === state.credentialSetup.profileId)) {
      state.credentialSetup = null;
    }
    return true;
  } catch (error) {
    state.profiles = [];
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
      appendLog("error", name, `Live stream unavailable: ${errorText(error)}`);
    }
  }
}

async function bootstrap() {
  bindGlobalEvents();
  await loadBootPayload();
  if (state.migrationHandoff) state.activePage = "general";
  await loadSettingsSnapshot();
  await loadPlatformDesign();
  await loadEngineStatus();
  await loadRetirementStatus();
  await loadNetworkDiagnostics();
  await loadProfilesSnapshot();
  await loadRuntimeProjection();
  renderPage();
  void (async () => {
    if (await loadControllerSnapshotWithRetry()) {
      await loadProvidersSnapshot();
      if (state.activePage === "rules") await loadRulesSnapshot();
    }
  })().finally(renderPage);

  document.getElementById("reload-button").addEventListener("click", reloadPayload);

  await listen("cfw://page", (event) => {
    state.activePage = event.payload;
    renderPage();
  });

  await listen("cfw://settings-changed", async (event) => {
    try {
      applyPersistedSettings(event.payload);
    } catch (error) {
      appendLog("error", "settings", `Rejected an invalid settings update: ${errorText(error)}`);
      try {
        await loadSettingsSnapshot();
        appendLog("warning", "settings", "Preferences were recovered from the native store after an invalid update event.");
      } catch (refreshError) {
        resetPersistedSettingsToSafeState();
        state.settingsUnavailableReason = "Preferences are unavailable because the native settings snapshot could not be verified. Reload from disk before changing them.";
        appendLog("error", "settings", `Native settings recovery failed: ${errorText(refreshError)}`);
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
        appendLog("warning", "profile", "Drag-drop requires a JSON, YAML, or node-link text profile");
      }
      return;
    }
    if (!engineIsOff()) {
      appendLog("warning", "profile", REASONS.engineNotOff);
      return;
    }
    for (const path of profilePaths) {
      await importProfileFromPath(path);
    }
  });

  criticalMigrationListenersBound = true;
  if (state.migrationHandoff) {
    // Close the snapshot/listener gap without requesting another boot challenge
    // in this renderer lifetime. A real WebView reload receives the next
    // parent-ticket-bound generation from its one bootstrap call.
    await loadRetirementStatus();
    renderPage();
  }
  await acknowledgeMigrationHandoffRendererReady();

  // Register every listener before the automatic check. The setup-time check
  // used to race this subscription and could lose the only availability event.
  if (state.toggles.checkForUpdates) {
    try {
      applyUpdateInfo(await invoke("check_for_updates"));
    } catch (error) {
      appendLog("error", "updater", `Automatic update check failed: ${errorText(error)}`);
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
    const result = await invoke("import_profile_file", { path, name: null, activate: true });
    await loadProfilesSnapshot();
    appendLog("info", "profile", `Dropped profile imported: ${result.name} (${formatBytes(result.bytes ?? 0)})`);
    await applyActiveProfile("importing a dropped profile");
    await openCredentialSetup(result.id);
    scheduleRender();
  } catch (error) {
    appendLog("error", "profile", `Drag-drop import failed: ${errorText(error)}`);
  }
}

export function renderFatalBootstrap() {
  document.body.innerHTML = `<pre class="fatal">${escapeHtml("Clash for Mac could not start safely (startup_state_unverifiable). Review the application log before retrying.")}</pre>`;
}

bootstrap().catch(() => {
  renderFatalBootstrap();
});
