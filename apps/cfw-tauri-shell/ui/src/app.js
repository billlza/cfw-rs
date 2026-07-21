import {
  fallbackPayload,
  fallbackSettingsSnapshot,
  fallbackCoreStatus,
  state,
  navInitials,
  primaryNavIds,
  MAX_LOG_ROWS,
  MAX_CONNECTION_ROWS,
  runtime,
} from "./state.js";

import {
  tauriApi,
  sleep,
  invoke,
  listen,
  escapeHtml,
  formatRuntime,
  serviceModeLabel,
  serviceModeNeedsAttention,
  tunModeValueLabel,
  formatGeoipLabel,
  formatBytes,
  formatRate,
  emptyProviderBatch,
  providerActionKey,
  providerBatchSummary,
  providerBatchSucceeded,
  latestDelay,
  normalizeLevel,
  safeRegex,
  pageById,
  activeProfile,
} from "./format.js";


function applyPersistedSettings(snapshot) {
  if (!snapshot?.settings) return;
  state.settingsSnapshot = snapshot;
  const settings = snapshot.settings;
  state.mode = settings.runtime_mode ?? state.mode;
  state.logLevel = settings.logLevel ?? settings["log-level"] ?? state.logLevel;
  state.toggles.systemProxy = Boolean(settings.system_proxy);
  state.toggles.tunMode = Boolean(settings.tun_mode);
  state.toggles.mixin = Boolean(settings.mixin);
  state.mixinYaml = settings.mixin_yaml ?? settings.mixinYaml ?? "";
  state.profileParserScript = settings.profile_parser_script ?? settings.profileParserScript ?? "";
  state.trayScript = settings.tray_script ?? settings.trayScript ?? "";
  state.childProcessCommand = settings.child_process_command ?? settings.childProcessCommand ?? "";
  state.toggles.allowLan = Boolean(settings.allow_lan);
  state.toggles.enableIpv6 = Boolean(settings.enable_ipv6);
  state.toggles.startAtLogin = Boolean(settings.launch_at_login);
  state.toggles.silentStart = Boolean(settings.silent_start);
  state.toggles.breakOnProxyChange = Boolean(settings.break_connections_on_proxy_change);
  state.toggles.proxyDelayIndicator = Boolean(settings.show_tray_proxy_delay_indicator);
  state.toggles.usePacScript = Boolean(settings.usePacScript ?? settings.use_pac_script);
  state.pacScript = settings.pacScript ?? settings.pac_script ?? state.pacScript ?? "";
  applyAppearance(settings);
}

function persistedSettingsFromUi() {
  const current = state.settingsSnapshot?.settings ?? fallbackSettingsSnapshot.settings;
  return {
    ...current,
    runtime_mode: state.mode,
    logLevel: state.logLevel,
    system_proxy: state.toggles.systemProxy,
    proxy_bypass: (document.querySelector("[data-proxy-bypass]")?.value ?? (state.settingsSnapshot?.settings?.proxy_bypass ?? []).join("\n"))
      .split(/[\n,]+/)
      .map((item) => item.trim())
      .filter(Boolean),
    tun_mode: state.toggles.tunMode,
    mixin: state.toggles.mixin,
    mixin_yaml: document.querySelector("[data-mixin-yaml]")?.value ?? state.mixinYaml ?? current.mixin_yaml ?? "",
    profile_parser_script: document.querySelector("[data-profile-parser-script]")?.value ?? state.profileParserScript ?? current.profile_parser_script ?? "",
    tray_script: document.querySelector("[data-tray-script]")?.value?.trim() ?? state.trayScript ?? current.tray_script ?? "",
    child_process_command: document.querySelector("[data-child-process-command]")?.value?.trim() ?? state.childProcessCommand ?? current.child_process_command ?? "",
    allow_lan: state.toggles.allowLan,
    enable_ipv6: state.toggles.enableIpv6,
    launch_at_login: state.toggles.startAtLogin,
    silent_start: state.toggles.silentStart,
    break_connections_on_proxy_change: state.toggles.breakOnProxyChange,
    show_tray_proxy_delay_indicator: state.toggles.proxyDelayIndicator,
    usePacScript: state.toggles.usePacScript,
    pacScript: document.querySelector("[data-pac-script]")?.value ?? state.pacScript ?? current.pacScript ?? current.pac_script ?? "",
    theme: document.querySelector("[data-theme-setting]")?.value ?? current.theme ?? "light",
    font_family: document.querySelector("[data-font-family]")?.value?.trim() ?? current.font_family ?? "",
    "interface-name": document.querySelector("[data-outbound-interface]")?.value?.trim() ?? current["interface-name"] ?? current.interfaceName ?? "",
    randomMixedPort: document.querySelector("[data-random-mixed-port]")?.checked
      ?? Boolean(current.randomMixedPort ?? current.random_mixed_port),
    delayTestUrl: document.querySelector("[data-delay-test-url]")?.value?.trim()
      || current.delayTestUrl
      || current.delay_test_url
      || "http://www.gstatic.com/generate_204",
    coreKind: document.querySelector("[data-core-kind]")?.value
      || current.coreKind
      || current.core_kind
      || "clash_rs",
    core_kind: document.querySelector("[data-core-kind]")?.value
      || current.coreKind
      || current.core_kind
      || "clash_rs",
  };
}

function applyAppearance(settings) {
  const theme = settings.theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = theme;
  const font = String(settings.font_family ?? settings.fontFamily ?? "").trim();
  document.documentElement.style.setProperty("--sans", font ? `"${font}", "Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif` : '"Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif');
}

function applyControllerSnapshot(snapshot) {
  if (!snapshot) return;

  const config = snapshot.config ?? {};
  const mode = config.mode ? config.mode[0].toUpperCase() + config.mode.slice(1).toLowerCase() : null;
  if (["Global", "Rule", "Direct", "Script"].includes(mode)) state.mode = mode;
  const allowLan = config["allow-lan"] ?? config.allow_lan;
  const mixedPort = config["mixed-port"] ?? config.mixed_port;
  if (typeof allowLan === "boolean") state.toggles.allowLan = allowLan;
  if (typeof config.ipv6 === "boolean") state.toggles.enableIpv6 = config.ipv6;
  if (config["log-level"] || config.log_level) state.logLevel = config["log-level"] ?? config.log_level;
  if (typeof mixedPort === "number") {
    state.settingsSnapshot.settings.mixed_port = mixedPort;
  }

  const proxyNodes = new Map((snapshot.proxies?.proxies ?? []).map((node) => [node.name, node]));
  const groups = snapshot.proxies?.groups ?? [];
  const groupsByName = new Map(groups.map((group) => [group.name, group]));
  // Always replace — empty groups must clear stale iKuuu UI after a failed/empty profile.
  state.proxyGroups = groups.map((group) => ({
    name: group.name,
    type: group.kind,
    now: group.now ?? group.options?.[0] ?? "DIRECT",
    options: (group.options ?? []).map((name) => {
      const node = proxyNodes.get(name);
      const nestedGroup = groupsByName.get(name);
      return {
        name,
        delay: latestDelay(node?.history ?? nestedGroup?.history ?? []),
        dead: false,
        kind: node?.kind ?? node?.type ?? nestedGroup?.kind ?? group.kind ?? "Proxy",
        udp: node?.udp ?? null,
      };
    }),
  }));

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
  return true;
}

function visibleLogs() {
  const regex = safeRegex(state.logSearch);
  return state.logs.filter((line) => {
    const matchesLevel = state.logFilter === "all" || line.level === state.logFilter;
    const haystack = [line.time, line.level, line.source, line.message, ...(line.fields ?? []).map((field) => `${field.key}=${field.value}`)].join(" ");
    const matchesSearch = !state.logSearch || (regex ? regex.test(haystack) : haystack.toLowerCase().includes(state.logSearch.toLowerCase()));
    return matchesLevel && matchesSearch;
  }).slice(0, MAX_LOG_ROWS);
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
  nav.innerHTML = state.payload.pages
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

function renderToggle(key, label, hint, options = {}) {
  const checked = state.toggles[key] ? "checked" : "";
  const disabled = options.disabled ? "disabled" : "";
  return `
    <label class="toggle-row ${options.disabled ? "disabled" : ""}">
      <span>
        <b>${escapeHtml(label)}</b>
        <small>${escapeHtml(hint)}</small>
      </span>
      <input type="checkbox" data-toggle="${escapeHtml(key)}" ${checked} ${disabled} />
      <i></i>
    </label>
  `;
}

function renderInlineSwitch(key, label, options = {}) {
  const checked = state.toggles[key] ? "checked" : "";
  const disabled = options.disabled ? "disabled" : "";
  return `
    <label class="inline-switch ${options.disabled ? "disabled" : ""}">
      <span class="visually-hidden">${escapeHtml(label)}</span>
      <input type="checkbox" data-toggle="${escapeHtml(key)}" ${checked} ${disabled} />
      <i></i>
    </label>
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

function bindAddressLabel(persisted) {
  const bind = persisted["bind-address"] ?? persisted.bindAddress ?? (state.toggles.allowLan ? "*" : "127.0.0.1");
  return String(bind);
}

function serviceModeIconTone(status) {
  if (status === "Enabled") return "ok";
  if (serviceModeNeedsAttention(status)) return "warn";
  return "muted";
}

function renderKernelCompareRow() {
  const report = state.kernelCompare;
  if (!report?.comparison) {
    return `
      <div class="cfw-row">
        <div class="cfw-row-left">Core Bench</div>
        <div class="cfw-row-right">
          <button type="button" class="cfw-text-button" data-action="load-kernel-compare">Load measured clash-rs vs mihomo</button>
        </div>
      </div>
    `;
  }
  const headline = report.comparison.headline ?? {};
  const narrative = report.comparison.narrative ?? {};
  const cold = headline.cold_start_speedup_x != null ? `${headline.cold_start_speedup_x}×` : "n/a";
  const api = headline.controller_api_speedup_x != null ? `${headline.controller_api_speedup_x}×` : "n/a";
  const weak = headline.weak_net_success_delta_pp != null
    ? `${headline.weak_net_success_delta_pp >= 0 ? "+" : ""}${headline.weak_net_success_delta_pp}pp`
    : "n/a";
  const measured = report.measured_at ? String(report.measured_at).slice(0, 10) : "local";
  return `
    <div class="cfw-row cfw-row-bench">
      <div class="cfw-row-left">
        <span>Core Bench</span>
        <span class="general-icons">
          ${generalIconButton("show-kernel-compare", "info", "Show measured clash-rs vs mihomo details")}
        </span>
      </div>
      <div class="cfw-row-right">
        <button type="button" class="cfw-text-button" data-action="show-kernel-compare" title="${escapeHtml(narrative.speed ?? "")} ${escapeHtml(narrative.weak_net ?? "")}">
          clash-rs ${escapeHtml(cold)} cold · ${escapeHtml(api)} API · weak-net ${escapeHtml(weak)} · ${escapeHtml(measured)}
        </button>
      </div>
    </div>
  `;
}

function applyUpdateInfo(payload) {
  if (!payload || typeof payload !== "object") return;
  state.updateInfo = {
    available: Boolean(payload.available),
    current: payload.current ?? state.payload?.product?.version,
    version: payload.version ?? null,
    notes: payload.notes ?? null,
    error: payload.error ?? null,
  };
}

async function loadKernelCompare(force = false) {
  if (state.kernelCompare && !force) return state.kernelCompare;
  try {
    state.kernelCompare = await invoke("kernel_compare_report");
    return state.kernelCompare;
  } catch (error) {
    appendLog("warning", "bench", `Kernel compare unavailable: ${error.message ?? String(error)}`);
    return null;
  }
}

async function promptInstallUpdate(result) {
  applyUpdateInfo(result);
  openProductAboutDialog({
    autoCheck: true,
    checking: false,
    result,
  });
}

function openProductAboutDialog(options = {}) {
  const product = state.payload?.product ?? fallbackPayload.product;
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
  state.glassDialog = {
    kind: "product-about",
    payload: {
      checking: Boolean(options.checking),
      autoCheck: Boolean(options.autoCheck),
      update,
    },
  };
  renderGlassOverlays();
}

function productAboutStatusText(payload) {
  if (payload?.checking) return "Checking for updates…";
  const update = payload?.update;
  if (update?.error) return `Update check failed: ${update.error}`;
  if (update?.available && update?.version) {
    return `Update available: v${update.version}`;
  }
  if (update && update.available === false) {
    return `You’re up to date (v${update.current ?? state.payload?.product?.version ?? "—"})`;
  }
  return "Check GitHub releases for new builds.";
}


function renderGeneral() {
  const persisted = state.settingsSnapshot?.settings ?? fallbackSettingsSnapshot.settings;
  const product = state.payload.product ?? fallbackPayload.product;
  const appVersion = product.version ?? "0.3.3";
  const update = state.updateInfo;
  const updateBadge = update?.available && update?.version
    ? `<button type="button" class="cfw-update-badge" data-action="check-for-updates" title="Update available — click to download">→ v${escapeHtml(String(update.version))}</button>`
    : "";
  const core = state.coreStatus ?? fallbackCoreStatus;
  const coreRunning = core.state === "Running";
  const controllerHost = persisted.external_controller_host ?? "127.0.0.1";
  const controllerPort = persisted.external_controller_port ?? 9090;
  const coreKind = persisted.coreKind ?? persisted.core_kind ?? "clash_rs";
  const coreVersion = state.controllerVersion?.version ?? (coreRunning ? "Connected" : core.state);
  const statusDot = coreRunning ? "cfw-status-dot on" : "cfw-status-dot";
  const logLevel = state.logLevel ?? persisted.logLevel ?? persisted["log-level"] ?? "info";
  const serviceMode = serviceModeLabel(state.serviceModeStatus);
  const serviceModeReady = state.serviceModeStatus === "Enabled";
  const randomPort = Boolean(persisted.randomMixedPort ?? persisted.random_mixed_port);
  const bind = bindAddressLabel(persisted);
  const serviceTone = serviceModeIconTone(state.serviceModeStatus);
  return `
    <div class="cfw-general-view">
      <section class="cfw-header">
        <div class="cfw-app-mark">${renderCatLogo()}</div>
        <div class="cfw-title">
          <span>Clash for Mac</span>
          <small>v${escapeHtml(appVersion)}${updateBadge}</small>
        </div>
      </section>

      <section class="cfw-content">
        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Port</span>
            <span class="general-icons">
              ${generalIconButton("copy-proxy-exports", "terminal", "Copy proxy export commands for Terminal")}
              ${generalIconButton("toggle-random-mixed-port", randomPort ? "sync" : "sync-off", "random mixed port", { active: randomPort })}
            </span>
          </div>
          <div class="cfw-row-right">
            <input class="cfw-number" data-mixed-port type="number" min="1" max="65535" value="${persisted.mixed_port}" aria-label="mixed-port" ${randomPort ? "disabled" : ""}>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Allow LAN</span>
            <span class="general-icons">
              ${generalIconButton("allow-lan-info", "info", "Turn on to listen on all interfaces by default, or else only listen on 127.0.0.1. Change Bind Address to pick an interface.")}
              ${generalIconButton("show-network-interfaces", "device-hub", "network interfaces")}
            </span>
          </div>
          <div class="cfw-row-right">
            <button type="button" class="cfw-text-button" data-action="edit-bind-address" title="Edit bind address">Bind: ${escapeHtml(bind)}</button>
            ${renderInlineSwitch("allowLan", "Allow LAN")}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Log Level</div>
          <div class="cfw-row-right">
            <select class="cfw-select" data-log-level>
              ${["info", "warning", "error", "debug", "trace", "silent"].map((level) => `
                <option value="${level}" ${logLevel === level ? "selected" : ""}>${level}</option>
              `).join("")}
            </select>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">IPv6</div>
          <div class="cfw-row-right">${renderInlineSwitch("enableIpv6", "IPv6")}</div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Clash Core</span>
            <span class="general-icons">
              ${generalIconButton("preview-runtime-config", "memory", "Preview the final configuration file that was submitted to Clash Core")}
              ${generalIconButton("dns-query", "dns", "Resolve a host using Clash core")}
              ${generalIconButton("script-test", "play", "Test script using by Script mode")}
            </span>
          </div>
          <div class="cfw-row-right">
            <button type="button" class="cfw-text-button core-version-link" data-action="open-controller-dashboard" title="Open controller dashboard">
              <i class="${statusDot}"></i>
              <span>${escapeHtml(String(coreKind))} · ${escapeHtml(coreVersion)}${coreRunning ? ` (${escapeHtml(String(controllerPort))})` : ""}</span>
            </button>
            <button type="button" class="general-icon" data-action="${core.state === "MissingBinary" ? "install-pinned-core" : coreRunning ? "stop-core" : "start-core"}" title="${coreRunning ? "Stop core" : core.state === "MissingBinary" ? "Install pinned core" : "Start core"}">${coreRunning ? "■" : "▶"}</button>
          </div>
        </div>

        ${renderKernelCompareRow()}

        <div class="cfw-row">
          <div class="cfw-row-left">Home Directory</div>
          <div class="cfw-row-right">
            <button class="cfw-text-button" data-action="open-home-directory">Open Folder</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">GeoIP Database</div>
          <div class="cfw-row-right">
            <button class="cfw-text-button" data-action="update-geoip-database" title="${state.geoipStatus?.path ? escapeHtml(state.geoipStatus.path) : "Download / refresh GeoIP database"}">${escapeHtml(formatGeoipLabel(state.geoipStatus, state.geoipUpdating))}</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Service Mode</span>
            <span class="general-icons">
              <span class="general-icon ${serviceTone}" title="Service Mode status">${generalIcon("public")}</span>
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${serviceMode}</span>
            <button class="cfw-text-button" data-action="manage-service-mode">Manage</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>TUN Mode</span>
            <span class="general-icons">
              ${generalIconButton("tun-info", "info", "To enable this mode, please install Service Mode first!")}
              ${generalIconButton("tun-settings", "settings", "Settings")}
              ${generalIconButton("tun-reset-dns", "history", "System DNS servers that will be set after TUN Mode is disabled")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${tunModeValueLabel(state.tunRuntime?.tun_mode ?? state.toggles.tunMode, state.serviceModeStatus, state.tunRuntime)}</span>
            ${renderInlineSwitch("tunMode", "TUN Mode", { disabled: !serviceModeReady })}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Mixin</span>
            <span class="general-icons">
              ${generalIconButton("mixin-info", "info", "Mixin merges YAML into the generated config before reload. Docs: profile mixin in Settings.")}
              ${generalIconButton("edit-mixin", "settings", "Edit Mixin content")}
            </span>
          </div>
          <div class="cfw-row-right">${renderInlineSwitch("mixin", "Mixin")}</div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">System Proxy</div>
          <div class="cfw-row-right">${renderInlineSwitch("systemProxy", "System Proxy")}</div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Start with macOS</div>
          <div class="cfw-row-right">${renderInlineSwitch("startAtLogin", "Start with macOS")}</div>
        </div>
      </section>
    </div>
  `;
}

function delayClass(delay) {
  if (delay === null || delay === undefined) return "pending";
  // Mihomo uses 0 for timeout; negative is our local failure marker — both are Timeout.
  if (delay <= 0) return "dead";
  if (delay < 80) return "fast";
  if (delay < 180) return "mid";
  return "slow";
}

function delayLabel(delay) {
  if (delay === null || delay === undefined) return "Pending";
  if (delay <= 0) return "Timeout";
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

function applyDelayToProxyNodes(name, delay) {
  const value = typeof delay === "number" && Number.isFinite(delay) ? delay : 0;
  state.proxyGroups.forEach((group) => {
    group.options.forEach((node) => {
      if (node.name === name) {
        node.delay = value;
        node.dead = value <= 0;
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
    for (const group of state.proxyGroups) {
      const node = group.options.find((item) => item.name === name);
      if (node) {
        delay = node.delay;
        break;
      }
    }
    el.className = delayClass(delay);
    el.textContent = delayLabel(delay);
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
    if (found && (found.delay === null || found.delay === undefined)) {
      applyDelayToProxyNodes(name, 0);
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
  // Mihomo reports timeout as delay 0; failures are normalized to 0 (Timeout).
  return typeof node.delay === "number" && node.delay <= 0;
}

function renderProxies() {
  const filter = state.proxyFilter.trim().toLowerCase();
  const groups = state.proxyGroups
    .map((group) => ({
      ...group,
      options: group.options.filter((node) => {
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
  const controllerLive = state.controllerStatus === "controller live" && state.proxyGroups.length > 0;
  const emptyMessage = state.controllerStatus === "controller live" && state.proxyGroups.length === 0
    ? "Active profile has no proxy groups. Switch to a subscription with nodes."
    : "Controller unavailable. No live proxy groups are being displayed.";
  const modeSwitch = controllerLive ? `
      <div class="mode-switch proxy-mode-header" role="group" aria-label="Proxy mode">
        ${["Global", "Rule", "Direct", "Script"].map((mode) => `
          <button class="${state.mode === mode ? "selected" : ""}" data-mode="${mode}">${mode} <span>${modeIcon(mode)}</span></button>
        `).join("")}
      </div>` : "";
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
                <button class="cfw-node-card ${activeGroup.now === node.name ? "selected" : ""} ${blinkNode === node.name ? "blink" : ""} ${manual ? "" : "readonly"}" data-proxy-node="${escapeHtml(node.name)}" ${manual ? `data-group="${escapeHtml(activeGroup.name)}" data-node="${escapeHtml(node.name)}"` : "disabled"} title="${manual ? "Select proxy" : "This Clash group type is controlled by the core"}">
                  <i></i>
                  <span>
                    <strong>${nodePrefix(node.name)}${escapeHtml(node.name)}</strong>
                    <small>${escapeHtml(node.kind ?? "Proxy")} ${node.udp === false ? "" : "<em>UDP</em>"}</small>
                  </span>
                  <b class="${delayClass(node.delay)}" data-proxy-delay="${escapeHtml(node.name)}">${delayLabel(node.delay)}</b>
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
  return { Global: "↗", Rule: "↝", Direct: "→", Script: "↭" }[mode] ?? "";
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

function subscriptionLabel(profile) {
  if (profile.updateInterval) return `interval ${profile.updateInterval}`;
  return profile.sourceUrl ? "remote" : "local";
}

/** Parse Clash `subscription-userinfo` header: upload=; download=; total=; expire=. */
function parseSubscriptionUserinfo(raw) {
  if (!raw || typeof raw !== "string") return null;
  const parts = Object.create(null);
  for (const chunk of raw.split(/[;\s]+/)) {
    const idx = chunk.indexOf("=");
    if (idx <= 0) continue;
    parts[chunk.slice(0, idx).trim().toLowerCase()] = chunk.slice(idx + 1).trim();
  }
  const upload = Number(parts.upload);
  const download = Number(parts.download);
  const total = Number(parts.total);
  const expire = Number(parts.expire);
  const used = (Number.isFinite(upload) ? upload : 0) + (Number.isFinite(download) ? download : 0);
  let percent = null;
  if (Number.isFinite(total) && total > 0) {
    percent = Math.max(0, Math.min(100, (used / total) * 100));
  }
  let expireDate = null;
  if (Number.isFinite(expire) && expire > 0) {
    const date = new Date(expire * 1000);
    if (!Number.isNaN(date.getTime())) {
      const pad = (n) => String(n).padStart(2, "0");
      expireDate = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
    }
  }
  return {
    used,
    total: Number.isFinite(total) && total > 0 ? total : null,
    percent,
    expireDate,
  };
}

function formatQuotaBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "0B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  // CFW-style: 29.8GB / 300.0GB (no space, one decimal for KB+)
  if (unit === 0) return `${Math.round(value)}B`;
  return `${value.toFixed(1)}${units[unit]}`;
}

function formatRelativeUpdated(epochSecs) {
  if (!Number.isFinite(epochSecs) || epochSecs <= 0) return "unknown";
  const deltaMs = Date.now() - epochSecs * 1000;
  if (deltaMs < 0) return new Date(epochSecs * 1000).toLocaleString();
  const seconds = Math.floor(deltaMs / 1000);
  if (seconds < 45) return "a few seconds";
  if (seconds < 90) return "1 minute";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
  if (seconds < 5400) return "1 hour";
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`;
  return new Date(epochSecs * 1000).toLocaleString();
}

function profileUsageSpans(profile) {
  const parsed = parseSubscriptionUserinfo(profile.subscriptionUserinfo);
  if (parsed && (parsed.total != null || parsed.expireDate)) {
    const spans = [];
    if (parsed.total != null) {
      spans.push(`<span>${escapeHtml(formatQuotaBytes(parsed.used))}</span>`);
      spans.push(`<span>${escapeHtml(formatQuotaBytes(parsed.total))}</span>`);
    } else {
      spans.push(`<span>${escapeHtml(formatQuotaBytes(parsed.used))}</span>`);
    }
    if (parsed.expireDate) {
      spans.push(`<span>${escapeHtml(parsed.expireDate)}</span>`);
    }
    return spans.join("");
  }
  return `
    <span>${escapeHtml(profile.traffic)}</span>
    <span>${profile.rules.toLocaleString()} rules</span>
    <span>${escapeHtml(subscriptionLabel(profile))}</span>
  `;
}

function profileProgressWidth(profile) {
  const parsed = parseSubscriptionUserinfo(profile.subscriptionUserinfo);
  if (parsed?.percent != null) return parsed.percent;
  return 0;
}

/** CFW profile context-menu items — same actions, macOS liquid-glass chrome. */
const PROFILE_MENU_ACTIONS = [
  { id: "select", label: "Select", icon: "check", needsInactive: true },
  { id: "open-web", label: "Open web page", icon: "home", remoteOnly: false, needsHomeWeb: true },
  { id: "edit", label: "Edit", icon: "edit" },
  { id: "edit-external", label: "Edit externally", icon: "edit" },
  { id: "update", label: "Update", icon: "refresh", remoteOnly: true },
  { id: "reveal", label: "Show in folder", icon: "folder" },
  { id: "diff", label: "Diff", icon: "diff", remoteOnly: true },
  { id: "proxies", label: "Edit proxies section", icon: "send" },
  { id: "rules", label: "Edit rules section", icon: "rules" },
  { id: "copy", label: "Copy", icon: "copy" },
  { id: "qrcode", label: "QRCode", icon: "qr", remoteOnly: true },
  { id: "parsers", label: "Parsers", icon: "tree", remoteOnly: true },
  { id: "run-script", label: "Run script", icon: "code" },
  { id: "settings", label: "Settings", icon: "gear" },
  { id: "delete", label: "Delete", icon: "trash", danger: true },
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

function openProfileContextMenu(id, clientX, clientY) {
  state.glassDialog = null;
  state.profileContextMenu = { id, x: clientX, y: clientY };
  renderGlassOverlays();
}

function renderGlassOverlays() {
  const root = document.getElementById("glass-menu-root");
  if (!root) return;

  const parts = [];
  if (state.profileContextMenu) {
    const profile = state.profiles.find((item) => item.id === state.profileContextMenu.id);
    if (profile) {
      const remote = Boolean(profile.sourceUrl);
      const items = PROFILE_MENU_ACTIONS.filter((action) => {
        if (action.needsHomeWeb && !profile.homeWeb) return false;
        if (action.remoteOnly && !remote) return false;
        if (action.needsInactive && profile.active) return false;
        return true;
      });
      const menuHtml = items.map((action) => `
        <button type="button" class="glass-menu-item ${action.danger ? "danger" : ""}" data-profile-menu="${action.id}" data-profile-id="${escapeHtml(profile.id)}">
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
          <p class="glass-dialog-copy">Are you sure to delete “${escapeHtml(profile.name)}”? This removes the managed YAML file.</p>
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
          <p class="glass-dialog-copy">Reset Clash for Mac settings to defaults? Imported profile files are kept, but the active profile pointer and runtime toggles reset.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>No</button>
            <button type="button" class="glass-btn danger" data-glass-reset-confirm>Yes</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "geoip") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Update GeoIP database">
          <h3>Update GeoIP database</h3>
          <p class="glass-dialog-copy">Leave URL blank to use MetaCubeX geoip.metadb.</p>
          <label>URL<input data-glass-geoip-url placeholder="https://..." value="" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-geoip-confirm>Update</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "preview-config") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="Runtime config preview">
          <h3>Runtime config preview</h3>
          <pre class="glass-code">${escapeHtml(dialog.payload ?? "")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            <button type="button" class="glass-btn" data-glass-copy-text>Copy</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "network-interfaces") {
      const rows = (dialog.payload ?? []).map((row) => `
        <tr>
          <td>${escapeHtml(row.service)}</td>
          <td>${escapeHtml(row.bsd_device ?? row.bsdDevice ?? "—")}</td>
          <td>${escapeHtml(row.service_type ?? row.serviceType ?? "—")}</td>
          <td>${row.is_default_route || row.isDefaultRoute ? "default" : ""}</td>
        </tr>`).join("");
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="Network interfaces">
          <h3>Network interfaces</h3>
          <p class="glass-dialog-copy">Default route: ${escapeHtml(dialog.defaultRoute ?? "unknown")}</p>
          <div class="glass-table-wrap"><table class="glass-table"><thead><tr><th>Service</th><th>Device</th><th>Type</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="4">No services</td></tr>'}</tbody></table></div>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button></div>
        </div>
      `);
    } else if (dialog.kind === "bind-address") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Bind address">
          <h3>Bind address</h3>
          <p class="glass-dialog-copy">Use 127.0.0.1 for localhost only, * for all interfaces, or a specific IP.</p>
          <label>Address<input data-glass-bind-address value="${escapeHtml(dialog.payload ?? "*")}" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-bind-confirm>Save</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "dns-query") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="DNS query">
          <h3>Resolve via Clash core</h3>
          <label>Name<input data-glass-dns-name value="${escapeHtml(dialog.payload?.name ?? "www.gstatic.com")}" /></label>
          <label>Type<input data-glass-dns-type value="${escapeHtml(dialog.payload?.type ?? "A")}" /></label>
          <pre class="glass-code">${escapeHtml(dialog.payload?.result ?? "Enter a name and Query.")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            <button type="button" class="glass-btn" data-glass-dns-confirm>Query</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "script-test") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Script test">
          <h3>Script mode test</h3>
          <p class="glass-dialog-copy">mihomo does not expose a dedicated Script-eval REST API. Switch mode to Script and use Rules / Connections for live match visibility. Optional: open Rules now.</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
            <button type="button" class="glass-btn" data-glass-open-rules>Open Rules</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "edit-mixin") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog glass-dialog-wide" role="dialog" aria-label="Edit Mixin">
          <h3>Edit Mixin content</h3>
          <textarea class="glass-textarea" data-glass-mixin-yaml rows="16" spellcheck="false">${escapeHtml(dialog.payload ?? "")}</textarea>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-mixin-confirm>Save</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "tun-settings") {
      const p = dialog.payload ?? {};
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="TUN settings">
          <h3>TUN settings</h3>
          <label>Stack
            <select data-glass-tun-stack>
              ${["mixed", "gvisor", "system", "lwip"].map((s) => `<option value="${s}" ${p.stack === s ? "selected" : ""}>${s}</option>`).join("")}
            </select>
          </label>
          <label class="glass-check"><input type="checkbox" data-glass-tun-auto-route ${p.autoRoute ? "checked" : ""} /> auto-route</label>
          <label class="glass-check"><input type="checkbox" data-glass-tun-strict-route ${p.strictRoute ? "checked" : ""} /> strict-route</label>
          <label>DNS hijack (one per line)<textarea data-glass-tun-dns-hijack rows="4" spellcheck="false">${escapeHtml(p.dnsHijack ?? "any:53\n[::]:53")}</textarea></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn" data-glass-tun-settings-confirm>Save</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "tun-reset-dns") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Restore DNS">
          <h3>Restore DNS after TUN off</h3>
          <p class="glass-dialog-copy">These servers are applied with networksetup when you click Apply (CFW manage_history). Use Empty to clear overrides.</p>
          <label>DNS servers<textarea data-glass-restore-dns rows="5" spellcheck="false">${escapeHtml(dialog.payload ?? "Empty")}</textarea></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Cancel</button>
            <button type="button" class="glass-btn ghost" data-glass-restore-dns-save>Save</button>
            <button type="button" class="glass-btn" data-glass-restore-dns-apply>Apply now</button>
          </div>
        </div>
      `);
    } else if (dialog.kind === "service-mode-manage") {
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="Service Mode">
          <h3>Service Mode</h3>
          <p class="glass-dialog-copy">Status: ${escapeHtml(serviceModeLabel(state.serviceModeStatus))}</p>
          <div class="glass-dialog-actions column">
            <button type="button" class="glass-btn" data-glass-service-install>Install / Enable</button>
            <button type="button" class="glass-btn ghost" data-glass-service-uninstall>Uninstall / Disable</button>
            <button type="button" class="glass-btn ghost" data-glass-service-login-items>Open Login Items</button>
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
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
      const product = state.payload?.product ?? fallbackPayload.product;
      const version = product.version ?? "0.3.3";
      const status = productAboutStatusText(dialog.payload);
      const update = dialog.payload?.update;
      const canInstall = Boolean(update?.available && update?.version && !dialog.payload?.checking);
      const notes = update?.notes ? `<p class="product-about-notes">${escapeHtml(String(update.notes).slice(0, 280))}</p>` : "";
      parts.push(`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog product-about" role="dialog" aria-label="About Clash for Mac">
          <div class="product-about-icon">${renderCatLogo()}</div>
          <div class="product-about-name">Clash for Mac</div>
          <div class="product-about-sub">Powered by clash-rs &amp; mihomo</div>
          <div class="product-about-meta">
            <div>版本 ${escapeHtml(String(version))}</div>
            <div>发布于 Jul 21, 2026</div>
          </div>
          <div class="product-about-status">${escapeHtml(status)}</div>
          ${notes}
          <div class="glass-dialog-actions column">
            ${canInstall ? `<button type="button" class="glass-btn" data-glass-install-update>Download &amp; Install v${escapeHtml(String(update.version))}</button>` : ""}
            <button type="button" class="glass-btn ghost" data-glass-check-update ${dialog.payload?.checking ? "disabled" : ""}>${dialog.payload?.checking ? "Checking…" : "Check for Update"}</button>
            <button type="button" class="glass-btn ghost" data-glass-dismiss>Close</button>
          </div>
          <div class="product-about-copy">© Clash for Mac · MIT</div>
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
        appendLog("error", "profile", `${action} failed: ${error.message ?? String(error)}`);
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
        const result = await invoke("import_profile_text", { name, body: text.body, activate: false });
        await loadProfilesSnapshot();
        closeGlassOverlays();
        appendLog("info", "profile", `Copied profile to ${result.name}`);
      } catch (error) {
        appendLog("error", "profile", `Copy failed: ${error.message ?? String(error)}`);
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
        appendLog("error", "profile", `Settings failed: ${error.message ?? String(error)}`);
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
        appendLog("error", "profile", `Delete failed: ${error.message ?? String(error)}`);
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
        appendLog("warning", "settings", "cfw-settings.yaml reset to defaults");
      } catch (error) {
        appendLog("error", "settings", `Reset failed: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-geoip-confirm]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (state.geoipUpdating) return;
      const custom = document.querySelector("[data-glass-geoip-url]")?.value?.trim() ?? "";
      closeGlassOverlays();
      state.geoipUpdating = true;
      renderPage();
      try {
        const result = await invoke("update_geoip_database", {
          url: custom ? custom : null,
        });
        state.geoipStatus = result.status;
        appendLog(
          "info",
          "geoip",
          `Updated ${result.status.file_name} (${formatBytes(result.bytes)}) from ${result.source_url}`,
        );
      } catch (error) {
        appendLog("warning", "geoip", `GeoIP update failed: ${error.message ?? String(error)}`);
      } finally {
        state.geoipUpdating = false;
        renderPage();
      }
    });
  });

  document.querySelectorAll("[data-glass-copy-text]").forEach((button) => {
    button.addEventListener("click", async () => {
      const textValue = state.glassDialog?.payload ?? document.querySelector(".glass-code")?.textContent ?? "";
      try {
        await navigator.clipboard.writeText(String(textValue));
        appendLog("info", "clipboard", "Copied dialog text");
      } catch (error) {
        appendLog("warning", "clipboard", error.message ?? String(error));
      }
    });
  });

  document.querySelectorAll("[data-glass-bind-confirm]").forEach((button) => {
    button.addEventListener("click", async () => {
      const address = document.querySelector("[data-glass-bind-address]")?.value?.trim() ?? "";
      try {
        const snapshot = await invoke("set_bind_address", { address });
        applyPersistedSettings(snapshot);
        closeGlassOverlays();
        appendLog("info", "settings", `Bind address set to ${address}`);
        if (activeProfile().active) await invoke("apply_active_profile");
      } catch (error) {
        appendLog("warning", "settings", `Bind address failed: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-dns-confirm]").forEach((button) => {
    button.addEventListener("click", async () => {
      const name = document.querySelector("[data-glass-dns-name]")?.value?.trim() ?? "";
      const type = document.querySelector("[data-glass-dns-type]")?.value?.trim() || "A";
      try {
        const result = await invoke("dns_query", { name, record_type: type, recordType: type });
        state.glassDialog = { kind: "dns-query", payload: { name, type, result: JSON.stringify(result, null, 2) } };
        renderGlassOverlays();
      } catch (error) {
        state.glassDialog = { kind: "dns-query", payload: { name, type, result: String(error.message ?? error) } };
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

  document.querySelectorAll("[data-glass-mixin-confirm]").forEach((button) => {
    button.addEventListener("click", async () => {
      const yaml = document.querySelector("[data-glass-mixin-yaml]")?.value ?? "";
      try {
        const snapshot = await invoke("write_settings_snapshot", {
          settings: { ...persistedSettingsFromUi(), mixin_yaml: yaml, mixinYaml: yaml },
        });
        applyPersistedSettings(snapshot);
        state.mixinYaml = yaml;
        closeGlassOverlays();
        appendLog("info", "settings", "Mixin YAML saved");
        if (state.toggles.mixin && activeProfile().active) {
          const applied = await invoke("apply_active_profile");
          appendLog("info", "settings", `Mixin reapplied (${formatBytes(applied.bytes ?? 0)})`);
        }
      } catch (error) {
        appendLog("warning", "settings", `Mixin save failed: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-glass-tun-settings-confirm]").forEach((button) => {
    button.addEventListener("click", async () => {
      const stack = document.querySelector("[data-glass-tun-stack]")?.value ?? "mixed";
      const autoRoute = Boolean(document.querySelector("[data-glass-tun-auto-route]")?.checked);
      const strictRoute = Boolean(document.querySelector("[data-glass-tun-strict-route]")?.checked);
      const dnsHijack = document.querySelector("[data-glass-tun-dns-hijack]")?.value ?? "any:53\n[::]:53";
      try {
        const current = persistedSettingsFromUi();
        const snapshot = await invoke("write_settings_snapshot", {
          settings: {
            ...current,
            "tun-stack": stack,
            tunStack: stack,
            "tun-auto-route": autoRoute,
            tunAutoRoute: autoRoute,
            "tun-strict-route": strictRoute,
            tunStrictRoute: strictRoute,
            "tun-dns-hijack": dnsHijack,
            tunDnsHijack: dnsHijack,
          },
        });
        applyPersistedSettings(snapshot);
        closeGlassOverlays();
        appendLog("info", "tun", `TUN settings saved (stack=${stack})`);
        if (state.toggles.tunMode) {
          try {
            await invoke("reapply_runtime_config");
            appendLog("info", "tun", "Runtime config reapplied (root core respawn when TUN owns core)");
          } catch (error) {
            appendLog("warning", "tun", `Reapply after TUN settings failed: ${error.message ?? String(error)}`);
          }
        }
      } catch (error) {
        appendLog("warning", "tun", `TUN settings failed: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  const saveRestoreDns = async (applyNow) => {
    const servers = document.querySelector("[data-glass-restore-dns]")?.value ?? "Empty";
    try {
      const current = persistedSettingsFromUi();
      const snapshot = await invoke("write_settings_snapshot", {
        settings: { ...current, "restore-dns-servers": servers, restoreDnsServers: servers },
      });
      applyPersistedSettings(snapshot);
      if (applyNow) {
        const result = await invoke("apply_restore_dns_servers", { servers });
        appendLog("info", "dns", result);
      } else {
        appendLog("info", "dns", "Restore DNS list saved");
      }
      closeGlassOverlays();
    } catch (error) {
      appendLog("warning", "dns", error.message ?? String(error));
    }
    renderPage();
  };
  document.querySelectorAll("[data-glass-restore-dns-save]").forEach((button) => {
    button.addEventListener("click", () => saveRestoreDns(false));
  });
  document.querySelectorAll("[data-glass-restore-dns-apply]").forEach((button) => {
    button.addEventListener("click", () => saveRestoreDns(true));
  });

  document.querySelectorAll("[data-glass-service-install]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        const status = await invoke("enable_service_mode");
        state.serviceModeStatus = status;
        appendLog("info", "service", `Service Mode: ${serviceModeLabel(status)}`);
      } catch (error) {
        appendLog("warning", "service", error.message ?? String(error));
      }
      closeGlassOverlays();
      renderPage();
    });
  });
  document.querySelectorAll("[data-glass-service-uninstall]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await invoke("disable_service_mode");
        state.serviceModeStatus = await invoke("service_mode_status");
        appendLog("info", "service", "Service Mode disabled");
      } catch (error) {
        appendLog("warning", "service", error.message ?? String(error));
      }
      closeGlassOverlays();
      renderPage();
    });
  });
  document.querySelectorAll("[data-glass-service-login-items]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await invoke("open_login_items_settings");
        appendLog("info", "service", "Opened Login Items settings");
      } catch (error) {
        appendLog("warning", "service", error.message ?? String(error));
      }
    });
  });

  document.querySelectorAll("[data-glass-check-update]").forEach((button) => {
    button.addEventListener("click", async () => {
      openProductAboutDialog({ autoCheck: true, checking: true, result: state.updateInfo });
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
        openProductAboutDialog({ autoCheck: true, checking: false, result });
      } catch (error) {
        appendLog("warning", "updater", `Update check failed: ${error.message ?? String(error)}`);
        openProductAboutDialog({
          autoCheck: true,
          checking: false,
          result: { available: false, error: error.message ?? String(error), current: state.payload?.product?.version },
        });
      }
    });
  });

  document.querySelectorAll("[data-glass-install-update]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        appendLog("info", "updater", "Downloading and installing update…");
        openProductAboutDialog({
          autoCheck: true,
          checking: true,
          result: { ...state.updateInfo, available: true },
        });
        await invoke("install_available_update");
      } catch (error) {
        appendLog("warning", "updater", `Install failed: ${error.message ?? String(error)}`);
        openProductAboutDialog({
          autoCheck: true,
          checking: false,
          result: { ...state.updateInfo, error: error.message ?? String(error) },
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
    case "open-web": {
      if (!profile.homeWeb) throw new Error("no profile-web-page-url for this subscription");
      await invoke("open_external_url", { url: profile.homeWeb });
      appendLog("info", "profile", `Opened web page for ${profile.name}`);
      return;
    }
    case "edit":
      await openProfileInspector(id, "edit");
      appendLog("info", "profile", `edit editor opened for ${profile.name}`);
      return;
    case "proxies":
      await openProfileInspector(id, "edit", "proxies");
      appendLog("info", "profile", `proxies section editor opened for ${profile.name}`);
      return;
    case "rules":
      await openProfileInspector(id, "edit", "rules");
      appendLog("info", "profile", `rules section editor opened for ${profile.name}`);
      return;
    case "edit-external":
      await invoke("open_profile_externally", { id });
      appendLog("info", "profile", `Opened ${profile.name} externally`);
      return;
    case "update": {
      if (!profile.sourceUrl) throw new Error("local profile has no subscription URL");
      const wasActive = profile.active;
      const result = await invoke("update_profile", { id });
      await loadProfilesSnapshot();
      if (wasActive) await invoke("apply_active_profile");
      appendLog("info", "profile", `${result.name} subscription updated${wasActive ? " and config.yaml reapplied" : ""}`);
      return;
    }
    case "reveal":
      await invoke("reveal_profile", { id });
      appendLog("info", "profile", `Show in folder: ${profile.name}`);
      return;
    case "diff":
      await openProfileInspector(id, "diff");
      appendLog("info", "profile", `Diff opened for ${profile.name}`);
      return;
    case "copy":
      state.glassDialog = { kind: "copy", id };
      renderGlassOverlays();
      return;
    case "qrcode":
      await openProfileInspector(id, "qrcode");
      appendLog("info", "profile", `QRCode opened for ${profile.name}`);
      return;
    case "parsers":
      await openProfileInspector(id, "parsers");
      appendLog("info", "profile", `Parsers opened for ${profile.name}`);
      return;
    case "run-script":
      await openProfileInspector(id, "parsers");
      if (profile.active) {
        await invoke("apply_active_profile");
        appendLog("info", "profile", `Run script: reapplied parsers/mixin for active profile ${profile.name}`);
      } else {
        appendLog("info", "profile", `Run script: parser pipeline runs on apply; select ${profile.name} to execute against config.yaml`);
      }
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

function renderProfiles() {
  return `
    <div class="profiles-layout">
      <section class="cfw-profile-remote">
        <div class="cfw-url-box">
          <input data-profile-url placeholder="Download from a URL" aria-label="Profile URL" />
          <button class="paste-icon" data-action="paste-profile-url" title="Paste URL">▣</button>
        </div>
        <button class="cfw-big-button" data-action="import-profile">Download</button>
        <button class="cfw-big-button" data-action="update-all-profiles">Update All</button>
        <button class="cfw-big-button" data-action="import-profile-file">Import</button>
        <input class="profile-file-hidden" data-profile-file type="file" accept=".yaml,.yml,text/yaml,application/x-yaml" aria-label="Local profile YAML" />
      </section>

      <section class="cfw-profile-list">
        ${state.profiles.length ? state.profiles.map((profile) => `
          <article class="cfw-profile-card ${profile.active ? "active" : ""}" data-profile-card="${escapeHtml(profile.id)}">
            <i></i>
            <div class="profile-card-main">
              <h3>${escapeHtml(profile.name)}</h3>
              <p>${escapeHtml(profile.sourceUrl ? hostFromUrl(profile.sourceUrl) : "local file")} (${escapeHtml(profile.updated)})</p>
              <div class="profile-usage">
                ${profileUsageSpans(profile)}
              </div>
              <div class="profile-progress" title="${profile.subscriptionUserinfo ? escapeHtml(profile.subscriptionUserinfo) : "No subscription usage quota"}"><b style="width:${profileProgressWidth(profile).toFixed(1)}%"></b></div>
            </div>
            <div class="profile-card-primary">
              ${profile.sourceUrl
                ? `<button data-update-profile="${escapeHtml(profile.id)}" title="Update subscription">⟳</button>`
                : `<button data-profile-action="edit" data-profile-id="${escapeHtml(profile.id)}" title="Edit local profile">‹›</button>`}
            </div>
          </article>
        `).join("") : `
          <div class="empty-profile-state">
            <p>No profiles found in the managed profiles directory.</p>
            <button data-action="migrate-legacy-profiles">Import CFW Profiles</button>
          </div>
        `}
      </section>
      ${renderProfileInspector()}
    </div>
  `;
}

function renderProfileInspector() {
  const inspector = state.profileInspector;
  if (!inspector) return "";
  const profile = inspector.profile ?? {};
  const title = `${profile.name ?? inspector.id} · ${inspector.mode}`;
  const sourceUrl = profile.source_url ?? profile.sourceUrl ?? null;
  const parserKeys = profile.body
    ? [...profile.body.matchAll(/^([A-Za-z0-9_-]+):/gm)].map((match) => match[1]).filter((key) => key.toLowerCase().includes("parser"))
    : [];

  let body = "";
  if (inspector.mode === "diff") {
    body = `
      <div class="profile-diff-grid">
        <div><p class="label">Managed YAML</p><pre>${escapeHtml(profile.body ?? "")}</pre></div>
        <div><p class="label">Generated config.yaml preview</p><pre>${escapeHtml(profile.generated_body ?? "")}</pre></div>
      </div>
    `;
  } else if (inspector.mode === "edit") {
    body = `
      <textarea class="profile-editor" data-profile-editor spellcheck="false">${escapeHtml(profile.body ?? "")}</textarea>
      <div class="row-actions">
        <button class="button" data-action="save-profile-editor">Save YAML</button>
        <button class="button ghost" data-action="close-profile-inspector">Close</button>
      </div>
    `;
  } else if (inspector.mode === "qrcode") {
    body = inspector.svg
      ? `<div class="profile-qr">${inspector.svg}</div><p class="muted">${escapeHtml(sourceUrl ?? "")}</p>`
      : `<p class="empty">${escapeHtml(inspector.error ?? "This local profile has no subscription URL.")}</p>`;
  } else if (inspector.mode === "parsers") {
    body = `
      <dl class="detail-grid">
        <div><dt>Parser keys</dt><dd>${parserKeys.length ? parserKeys.map(escapeHtml).join(", ") : "none in this profile"}</dd></div>
        <div><dt>Execution</dt><dd>Parser scripts are treated as config transformation metadata only; arbitrary script execution is not enabled from the dashboard.</dd></div>
      </dl>
    `;
  } else {
    body = `
      <dl class="detail-grid">
        <div><dt>ID</dt><dd>${escapeHtml(profile.id ?? inspector.id)}</dd></div>
        <div><dt>Path</dt><dd>${escapeHtml(profile.path ?? "")}</dd></div>
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
  return `
    <div class="providers-layout">
      <section class="panel toolbar-panel">
        <div>
          <p class="label">Providers</p>
          <h3>Proxy Providers</h3>
          <p class="muted">Matches the original Proxy Providers / Rule Providers split and keeps Update All / Health Check All visible.</p>
        </div>
        <div class="toolbar-actions">
          <button class="button" data-action="update-all-providers" ${updatingAll ? "disabled" : ""}>${updatingAll ? "Updating..." : "Update All"}</button>
          <button class="button ghost" data-action="health-check-all" ${healthAll ? "disabled" : ""}>${healthAll ? "Checking..." : "Health Check All"}</button>
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
                <button class="button ghost" data-provider-update="${escapeHtml(provider.name)}" ${updating ? "disabled" : ""}>${updating ? "Updating" : "Update"}</button>
                <button class="button" data-provider-health="${escapeHtml(provider.name)}" ${checking ? "disabled" : ""}>${checking ? "Checking" : "Health Check"}</button>
              </div>
            </article>
          `;
        }).join("") : `
          <article class="panel provider-row empty-state">
            <div>
              <p class="label">Controller</p>
              <h3>No proxy providers loaded</h3>
              <p class="muted">This is now driven by /providers/proxies; no fake provider rows are rendered when Clash has none.</p>
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
                <button class="button ghost" data-rule-provider-update="${escapeHtml(provider.name)}" ${updating ? "disabled" : ""}>${updating ? "Updating" : "Update"}</button>
              </div>
            </article>
          `;
        }).join("") : `
          <article class="panel provider-row empty-state">
            <div>
              <p class="label">Controller</p>
              <h3>No rule providers loaded</h3>
              <p class="muted">This list is live from /providers/rules and stays empty when the active config has no rule providers.</p>
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
        <div class="segmented">
          ${["all", "info", "debug", "warning", "error"].map((level) => `
            <button class="${state.logFilter === level ? "selected" : ""}" data-log-filter="${level}">${level.toUpperCase()}</button>
          `).join("")}
        </div>
        <div class="toolbar-actions">
          <button class="button ghost" data-action="toggle-log-stream">${state.logsPaused ? "Start" : "Stop"}</button>
          <button class="button ghost" data-action="copy-logs">Copy</button>
          <button class="button ghost" data-action="reveal-logs">Open Folder</button>
          <button class="button ghost" data-action="clear-logs">Clear</button>
        </div>
      </section>

      <section class="panel log-stream">
        ${logs.map((line) => `
          <article class="log-line ${escapeHtml(line.level)}">
            <time>${escapeHtml(line.time)}</time>
            <b>${escapeHtml(line.level)}</b>
            <span>${escapeHtml(line.source)}</span>
            <p>
              ${escapeHtml(line.message)}
              ${(line.fields ?? []).length ? `<small>${line.fields.map((field) => `${escapeHtml(field.key)}=${escapeHtml(field.value)}`).join(" · ")}</small>` : ""}
            </p>
          </article>
        `).join("") || '<p class="empty">No logs for this filter.</p>'}
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
          <p class="muted">Live data from Clash controller /rules, including rule type, payload, proxy target and hit counters when exposed by the core.</p>
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

function renderNetworkDiagnostics() {
  const diagnostics = state.networkDiagnostics;
  if (!diagnostics) {
    return renderSettingsGroup("Network Diagnostics", [
      renderSettingValue("Default Route", "Unavailable", "Run inside the Tauri app to inspect macOS service order."),
    ]);
  }

  const services = diagnostics.services ?? [];
  const recommended = diagnostics.recommended_clash_proxy_services ?? [];
  const rows = [
    renderSettingValue("Default Route", diagnostics.default_route_interface ?? "unknown", "BSD interface used by the active default route."),
    renderSettingValue("Proxy Target", recommended.length ? recommended.join(", ") : "fallback to active services", "System Proxy now prefers the default-route service before touching other services."),
  ];

  rows.push(...services.map((service) => {
    const protocols = [service.proxy?.web, service.proxy?.secure_web, service.proxy?.socks].filter(Boolean);
    const managed = protocols.some((protocol) => protocol.managed_by_clash);
    const external = !managed && protocols.some((protocol) => protocol.enabled);
    const stateText = managed ? "Clash" : external ? "External" : "Off";
    const device = [service.hardware_port, service.bsd_device].filter(Boolean).join(" / ") || service.service_type || "unknown";
    const route = service.is_default_route ? "default route" : `order ${service.service_order ?? "-"}`;
    return renderSettingValue(service.service, `${stateText} · ${device}`, `${route}; bypass ${service.bypass_domains?.length ?? 0} domain(s).`);
  }));

  return renderSettingsGroup("Network Diagnostics", rows);
}

function renderMixinSettings() {
  return `
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Mixin</p>
          <h3>YAML Merge Before Apply</h3>
          <p class="muted">When Mixin is enabled, this YAML mapping is recursively merged into generated config.yaml before the core reloads.</p>
        </div>
        ${renderToggle("mixin", "Mixin", "Enable runtime YAML merge.")}
      </div>
      <textarea class="mixin-editor" data-mixin-yaml spellcheck="false" placeholder="dns:\n  enable: true\nprofile:\n  store-selected: true">${escapeHtml(state.mixinYaml ?? "")}</textarea>
    </section>
  `;
}

function renderProfileParserSettings() {
  return `
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Profile Parser</p>
          <h3>Safe Parser Script Before Mixin</h3>
          <p class="muted">Runs when previewing or applying profiles. Supported commands: set, delete, append, prepend, append-rule, prepend-rule, merge.</p>
        </div>
        <span class="badge">raw → parser → mixin → runtime</span>
      </div>
      <textarea class="mixin-editor" data-profile-parser-script spellcheck="false" placeholder="prepend-rule DOMAIN-SUFFIX,example.com,DIRECT&#10;set dns.enable true&#10;delete proxy-providers">${escapeHtml(state.profileParserScript ?? "")}</textarea>
    </section>
  `;
}

function renderActionRunnerSettings() {
  return `
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">Actions</p>
          <h3>Tray Script & Child Process</h3>
          <p class="muted">Commands run through the typed Rust action runner, not from renderer-side eval.</p>
        </div>
        <div class="toolbar-actions">
          <button class="button ghost" data-action="run-tray-script">Run Tray Script</button>
          <button class="button ghost" data-action="run-child-process">Run Child</button>
        </div>
      </div>
      ${renderSettingInput("Tray Script", state.trayScript, "/usr/bin/say 'Clash for Mac'", "Absolute executable path plus arguments; shell expansion is intentionally disabled.", "data-tray-script")}
      ${renderSettingInput("Child Process", state.childProcessCommand, "/usr/bin/env", "Lifecycle command staged for helper/service mode experiments.", "data-child-process-command")}
    </section>
  `;
}

function renderFeedback() {
  const product = state.payload.product ?? fallbackPayload.product;
  const update = state.updateInfo;
  const updateLine = update?.available && update?.version
    ? `New version available: v${escapeHtml(String(update.version))} (current v${escapeHtml(String(update.current ?? product.version ?? "0.3.3"))}).`
    : `Current build v${escapeHtml(product.version ?? "0.3.3")} — menu bar Clash for Mac → Check for Update… also works.`;
  const bench = state.kernelCompare?.comparison;
  const benchHtml = bench
    ? `<p class="muted">${escapeHtml(bench.narrative?.speed ?? "")}</p>
       <p class="muted">${escapeHtml(bench.narrative?.stability ?? "")}</p>
       <p class="muted">${escapeHtml(bench.narrative?.weak_net ?? "")}</p>
       <p class="muted">Measured ${escapeHtml(String(state.kernelCompare.measured_at ?? "local"))}. Not a CFW 3× claim.</p>`
    : `<p class="muted">Measured report not loaded yet.</p>`;
  return `
    <div class="feedback-layout">
      <section class="panel hero-panel">
        <div>
          <p class="label">Feedback</p>
          <h3>${escapeHtml(product.name)} v${escapeHtml(product.version ?? "0.3.3")}${update?.available && update?.version ? ` → v${escapeHtml(String(update.version))}` : ""}</h3>
          <p class="muted">Parity target is CFW 0.20.39; this build is the Apple Silicon beta (${escapeHtml(product.version ?? "0.3.3")}).</p>
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
        <p class="label">Measured</p>
        <h3>clash-rs vs mihomo</h3>
        ${benchHtml}
        <div class="toolbar-actions">
          <button class="button ghost" data-action="show-kernel-compare">Show Bench Details</button>
        </div>
      </section>

      <section class="panel">
        <p class="label">Parity source</p>
        <h3>CFW 0.20.39 (reference)</h3>
        <p class="muted">${escapeHtml(product.parity_source ?? "reverse artifact")}</p>
        <dl class="ports-list feedback-list">
          <div><dt>main</dt><dd>reverse/cfw-0.20.39-arm64/asar/main.js</dd></div>
          <div><dt>renderer</dt><dd>reverse/cfw-0.20.39-arm64/asar/renderer.js</dd></div>
          <div><dt>window</dt><dd>850 x 603 min frameless baseline</dd></div>
          <div><dt>routes</dt><dd>general / proxy / provider / log / server / connection / router / setting / about</dd></div>
        </dl>
      </section>
    </div>
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

function renderSettingInput(label, value, placeholder, hint, dataAttribute) {
  return `
    <label class="setting-row setting-control-row">
      <span>
        <b>${escapeHtml(label)}</b>
        <small>${escapeHtml(hint)}</small>
      </span>
      <input class="setting-input" ${dataAttribute} value="${escapeHtml(value ?? "")}" placeholder="${escapeHtml(placeholder ?? "")}" />
    </label>
  `;
}

function renderSettingSelect(label, value, options, hint, dataAttribute) {
  return `
    <label class="setting-row setting-control-row">
      <span>
        <b>${escapeHtml(label)}</b>
        <small>${escapeHtml(hint)}</small>
      </span>
      <select class="setting-input" ${dataAttribute}>
        ${options.map((option) => `<option value="${escapeHtml(option.value)}" ${option.value === value ? "selected" : ""}>${escapeHtml(option.label)}</option>`).join("")}
      </select>
    </label>
  `;
}

function renderSettingAction(label, value, hint, action, buttonLabel) {
  return `
    <div class="setting-row">
      <span>
        <b>${escapeHtml(label)}</b>
        <small>${escapeHtml(hint)}</small>
      </span>
      <span class="setting-action">
        <strong>${escapeHtml(value)}</strong>
        <button class="button ghost" data-action="${escapeHtml(action)}">${escapeHtml(buttonLabel)}</button>
      </span>
    </div>
  `;
}

function renderQuality() {
  const quality = state.payload.quality ?? fallbackPayload.quality;
  const perf = quality.performance;
  const stability = quality.stability;
  return `
    <section class="panel quality-panel">
      <div>
        <p class="label">Quality target</p>
        <h3>Interim quality budgets (target ${perf.multiplier_vs_cfw_02039}× vs CFW 0.20.39)</h3>
        <p class="muted">These are engineering budgets, not yet proven with side-by-side benchmarks on this machine.</p>
      </div>
      <dl class="budget-grid">
        <div><dt>Cold start p95</dt><dd>${perf.cold_start_p95_ms} ms</dd></div>
        <div><dt>Page switch p95</dt><dd>${perf.page_switch_p95_ms} ms</dd></div>
        <div><dt>Proxy toggle p95</dt><dd>${perf.proxy_toggle_p95_ms} ms</dd></div>
        <div><dt>Idle RSS cap</dt><dd>${perf.max_idle_rss_mb} MB</dd></div>
        <div><dt>Crash-free sessions</dt><dd>${(stability.crash_free_session_rate_basis_points / 100).toFixed(2)}%</dd></div>
        <div><dt>Proxy restore</dt><dd>${stability.restore_system_proxy_on_exit ? "Required" : "Missing"}</dd></div>
      </dl>
    </section>
  `;
}

function renderSettings() {
  const platform = state.payload.platform ?? fallbackPayload.platform;
  const snapshot = state.settingsSnapshot ?? fallbackSettingsSnapshot;
  const persisted = snapshot.settings ?? fallbackSettingsSnapshot.settings;
  const paths = snapshot.paths ?? fallbackSettingsSnapshot.paths;
  const controller = `${persisted.external_controller_host}:${persisted.external_controller_port}`;
  const outboundInterface = persisted["interface-name"] ?? persisted.interfaceName ?? "";
  const recommendedInterface = state.networkDiagnostics?.default_route_interface ?? "auto";
  const theme = persisted.theme === "dark" ? "dark" : "light";
  const fontFamily = persisted.font_family ?? persisted.fontFamily ?? "";
  const paritySettingsGroups = [
    ["Security", [renderSettingValue("Core Secret", persisted.secret ? "random UUID" : "not set", "Protect Clash REST API with a random RFC4122 UUID.")]],
    ["Appearance", [
      renderSettingSelect("Theme", theme, [{ value: "light", label: "Light" }, { value: "dark", label: "Dark" }], "Persisted app theme applied at boot.", "data-theme-setting"),
      renderSettingInput("Font", fontFamily, "Avenir Next", "Override dashboard font family; blank uses the CFW-like default.", "data-font-family"),
    ]],
    ["System Proxy", [
      renderToggle("systemProxy", "System Proxy", "Enable macOS system HTTP/HTTPS/SOCKS proxy."),
      renderToggle("proxyDelayIndicator", "Tray delay indicator", "Show selected-node latency in the menu-bar title/tooltip."),
      renderToggle("usePacScript", "Use PAC Script", "When System Proxy is on, apply Auto Proxy URL (PAC) instead of manual HTTP/HTTPS/SOCKS."),
      (() => {
        const bypass = (persisted.proxy_bypass ?? []).join("\n");
        const pac = persisted.pacScript ?? persisted.pac_script ?? state.pacScript ?? "";
        return `
          <label class="setting-row setting-control-row">
            <span>
              <b>Bypass Domains</b>
              <small>One host or CIDR per line. Empty uses the built-in LAN/localhost defaults. Applied when System Proxy turns on (manual mode).</small>
            </span>
            <textarea class="mixin-editor" data-proxy-bypass spellcheck="false" rows="5">${escapeHtml(bypass)}</textarea>
          </label>
          <label class="setting-row setting-control-row">
            <span>
              <b>PAC Script</b>
              <small>FindProxyForURL body. Empty generates PROXY/SOCKS5 for the current mixed-port. Written to app-home proxy.pac when Use PAC Script is on.</small>
            </span>
            <textarea class="mixin-editor" data-pac-script spellcheck="false" rows="8" placeholder="function FindProxyForURL(url, host) {&#10;  return &quot;PROXY 127.0.0.1:7890; SOCKS5 127.0.0.1:7890; DIRECT&quot;;&#10;}">${escapeHtml(pac)}</textarea>
          </label>`;
      })(),
    ]],
    ["Mixin", [renderToggle("mixin", "Mixin", "Merge YAML/JS mixin before profile apply."), renderSettingValue("Mixin YAML", "Editor active", "The YAML merge editor below is persisted and applied before config reload.")]],
    ["Proxies", [
      renderToggle("hideUnavailable", "Hide timed-out proxies", "Hide nodes that failed latency tests (Timeout), matching CFW Show/Hide timed-out proxies."),
      renderSettingInput(
        "Delay test URL",
        persisted.delayTestUrl ?? persisted.delay_test_url ?? "http://www.gstatic.com/generate_204",
        "http://www.gstatic.com/generate_204",
        "Used by Proxies → Delay Test against the live controller.",
        "data-delay-test-url"
      ),
    ]],
    ["Connections", [
      renderToggle("breakOnProxyChange", "Break connections", "Disconnect sockets after proxy or profile changes."),
      renderToggle("showProcess", "Show Process", "Show connection process name from metadata.processPath when the core reports it."),
    ]],
    ["Providers", [renderSettingValue("Use CFW Editor", "Profile editor active", "Profile YAML edit/diff is built in; provider file editor remains behind controller metadata."), renderSettingValue("Update All", "Controller-backed", "Proxy and rule providers expose bulk update actions.")]],
    ["Outbound", [renderSettingInput("Interface Name", outboundInterface, recommendedInterface, "Bind Clash outbound sockets to a macOS BSD interface; blank keeps Clash automatic.", "data-outbound-interface")]],
    ["Child Processes", [renderSettingValue("Processes", "Action runner", "Spawn child processes through a typed Rust command boundary.")]],
    ["Profiles", [renderSettingValue("Parsers", "Safe script active", "Apply parser scripts before mixin/runtime config generation."), renderSettingValue("Headers", "Captured", "Remote imports persist subscription-userinfo and profile-update-interval metadata.")]],
    ["Logs", [renderSettingValue("Request Logs", "Preload + stream", "Original supports log preload, filters and log-level changes.")]],
    ["SSID", [renderSettingValue("SSID Policy", "Not in 0.2.0", "CFW could vary proxy/profile by Wi-Fi SSID. Deferred — this toggle is intentionally unavailable.")]],
    ["Actions", [renderSettingValue("Tray Script", "Rust action runner", "Run Tray Script action is executable from settings and tray.")]],
    ["Shortcuts", [renderSettingValue("Mode shortcuts", "Active", "Cmd+1..6, Cmd+G/R/D/S/P/T/M mirror original dashboard shortcuts.")]],
    ["CFW Editor", [renderSettingValue("Diff Editor", "Not in 0.2.0", "Built-in YAML edit exists on Profiles; Monaco-style side-by-side diff is deferred.")]],
    ["Cache", [renderSettingAction("Fake IP Cache", "Controller-backed", "Flush Mihomo fake-ip cache through /cache/fakeip/flush.", "flush-fake-ip-cache", "Flush")]],
    ["Experimental Features", [renderSettingValue("DHCP Server", "Not in 0.2.0", "CFW macOS DHCP server switch is not shipped in this beta."), renderToggle("enableIpv6", "IPv6", "Expose IPv6 option in generated Clash config.")]],
  ];
  const serviceMode = serviceModeLabel(state.serviceModeStatus);
  return `
    <div class="settings-layout">
      <section class="panel toolbar-panel settings-toolbar">
        <div>
          <p class="label">Settings Store</p>
          <h3>${snapshot.persisted ? "cfw-settings.yaml loaded" : "Defaults staged"}</h3>
          <p class="muted">${escapeHtml(paths.settings_file)}${snapshot.persisted ? "" : " will be created on save."}</p>
        </div>
        <div class="toolbar-actions">
          <button class="button ghost danger" data-action="reset-settings">Reset All Settings</button>
          <button class="button" data-action="save-settings">Save Settings</button>
          <button class="button ghost" data-action="reload-settings">Reload From Disk</button>
          <button class="button ghost" data-action="force-quit-app">Force Quit</button>
          <button class="button ghost" data-action="quit-app">Quit</button>
        </div>
      </section>
      ${renderSettingsGroup("General", [
        renderToggle("startAtLogin", "Start at Login", "Launch Clash for Mac after login via SMAppService Login Item."),
        renderToggle("silentStart", "Silent Start", "Start hidden in tray without Dock bounce (Accessory policy)."),
        renderToggle("proxyDelayIndicator", "Tray delay indicator", "Show current proxy latency in tray quick menu."),
        renderSettingAction("Updates", "GitHub Releases", "Check tauri-plugin-updater against the latest signed release.", "check-for-updates", "Check for Updates"),
      ])}
      ${renderSettingsGroup("Core", [
        renderSettingValue("mixed-port", String(persisted.mixed_port), "HTTP, HTTPS and SOCKS entry point."),
        renderSettingValue("external-controller", controller, "Local Clash controller endpoint."),
        renderSettingValue("secret", persisted.secret ? "••••••••" : "empty", "Controller secret stored in cfw-settings.yaml."),
        `
          <div class="settings-row">
            <div>
              <p class="settings-title">Core engine</p>
              <p class="muted">Default is clash-rs (Rust). Mihomo is automatic fallback. Env: CFW_CORE_KIND.</p>
            </div>
            <select data-core-kind class="settings-select">
              <option value="clash_rs" ${(persisted.coreKind ?? persisted.core_kind ?? "clash_rs") === "clash_rs" ? "selected" : ""}>clash-rs (default, Rust)</option>
              <option value="mihomo" ${(persisted.coreKind ?? persisted.core_kind) === "mihomo" ? "selected" : ""}>mihomo (fallback)</option>
            </select>
          </div>
        `,
        renderToggle("enableIpv6", "IPv6", "Expose IPv6 option in generated Clash config."),
        renderSettingAction("Install clash-rs", "Apple Silicon only", `Download pinned clash-rs ${"v0.10.7"} beside mihomo (does not change default).`, "install-pinned-clash-rs", "Install"),
      ])}
      ${renderMixinSettings()}
      ${renderProfileParserSettings()}
      ${renderActionRunnerSettings()}
      ${renderSettingsGroup("Paths", [
        renderSettingValue("Home Directory", paths.app_home, "macOS application support root."),
        renderSettingValue("Settings", paths.settings_file, "Clash for Mac shell settings."),
        renderSettingValue("Profiles", paths.profiles_dir, "Imported and generated profile files."),
        renderSettingValue("Logs", paths.logs_dir, "Core, shell and helper logs."),
        renderSettingValue("Cores", paths.cores_dir, "Apple Silicon Clash core binaries."),
        renderSettingValue("Helpers", paths.helpers_dir, "Privileged helper payload staging."),
      ])}
      ${renderSettingsGroup("macOS", [
        renderSettingValue("Minimum macOS", platform.minimum_macos ?? "13.0", "ARM64-only app baseline."),
        renderSettingValue("Intel support", platform.intel_supported ? "Enabled" : "Disabled", "Removed to optimize Apple Silicon runtime."),
        renderSettingValue("System proxy", platform.system_proxy_strategy ?? "native manager", "Rust SystemConfiguration boundary."),
        renderSettingValue("Service Mode", serviceMode, "Live SMAppService status for the privileged helper."),
        renderSettingAction("Service Mode", serviceMode, "Register the SMAppService helper (approve under Login Items if prompted).", "manage-service-mode", "Manage"),
      ])}
      ${renderNetworkDiagnostics()}
      ${renderSettingsGroup("Experimental", [
        renderToggle("hideUnavailable", "Hide timed-out proxies", "Hide nodes that failed latency tests (Timeout)."),
        renderSettingValue("TUN", platform.tun_strategy ?? "SmAppServiceRootHelper", "Production TUN path: SMAppService root helper (not Network Extension)."),
        renderSettingValue("UI shell", "Tauri 2 + WebKit", "Native Tauri shell. React is not the product UI."),
        renderSettingValue("launchd", platform.launchd_strategy ?? "typed launchd contract", "No product-layer ad-hoc scripts."),
      ])}
      <section class="panel settings-index">
        <div class="section-heading">
          <div>
            <p class="label">Original Settings Taxonomy</p>
            <h3>CFW Setting Groups</h3>
          </div>
          <span class="badge">${paritySettingsGroups.length} groups</span>
        </div>
        <div class="settings-taxonomy">
          ${paritySettingsGroups.map(([title, rows]) => `
            <article class="taxonomy-group">
              <h4>${escapeHtml(title)}</h4>
              ${rows.join("")}
            </article>
          `).join("")}
        </div>
      </section>
      ${renderQuality()}
      <section class="panel deep-link-panel">
        <div class="section-heading">
          <div>
            <p class="label">clash:// protocol</p>
            <h3>Deep link events</h3>
          </div>
          <button class="button ghost" data-action="clear-deep-links">Clear</button>
        </div>
        <pre>${state.deepLinks.length ? escapeHtml(JSON.stringify(state.deepLinks, null, 2)) : "No deep links received yet."}</pre>
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

function renderPage() {
  const page = pageById(state.activePage);
  document.title = "";
  const productName = document.getElementById("product-name");
  if (productName) productName.textContent = state.payload.product?.name ?? "Clash for Mac";
  const statusTitle = document.getElementById("status-title");
  if (statusTitle) statusTitle.textContent = `${page.title} - ${state.mode} Mode`;
  document.getElementById("page-title").textContent = page.title;
  document.getElementById("page-summary").textContent = page.summary;
  const running = state.coreStatus?.state === "Running";
  const sidebarStatus = document.getElementById("sidebar-status");
  if (sidebarStatus) sidebarStatus.textContent = running ? "Connected" : "Disconnected";
  const sidebarDot = document.getElementById("sidebar-status-dot");
  if (sidebarDot) sidebarDot.className = running ? "on" : "";
  updateStatusBar();

  renderNav();
  document.getElementById("page").innerHTML = (pageRenderers[state.activePage] ?? renderGeneral)();
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

async function selectProfileById(id) {
  const profile = state.profiles.find((item) => item.id === id);
  if (!profile) throw new Error(`profile not found: ${id}`);
  if (profile.active) {
    appendLog("info", "profile", `${profile.name} is already active`);
    return false;
  }
  const previousActiveProfile = activeProfile().active ? activeProfile().id : null;
  const snapshot = await invoke("write_settings_snapshot", {
    settings: { ...persistedSettingsFromUi(), active_profile: id },
  });
  applyPersistedSettings(snapshot);
  await loadProfilesSnapshot();
  try {
    const applied = await invoke("apply_active_profile");
    appendLog(
      "info",
      "profile",
      `Profile switched to ${activeProfile().name}; config.yaml updated (${formatBytes(applied.bytes ?? 0)})`,
    );
    await loadControllerSnapshotWithRetry(state.toggles.tunMode ? 10 : 6, 500);
    if (state.toggles.breakOnProxyChange) {
      await closeConnectionsAfterProxyChange("profile");
    }
    return true;
  } catch (error) {
    const rollback = await invoke("write_settings_snapshot", {
      settings: { ...persistedSettingsFromUi(), active_profile: previousActiveProfile },
    });
    applyPersistedSettings(rollback);
    await loadProfilesSnapshot();
    if (previousActiveProfile) {
      try {
        await invoke("apply_active_profile");
      } catch (reapplyError) {
        appendLog(
          "warning",
          "profile",
          `Rollback re-apply failed: ${reapplyError.message ?? String(reapplyError)}`,
        );
      }
    }
    await loadControllerSnapshotWithRetry(6, 400).catch(() => false);
    appendLog(
      "error",
      "profile",
      `Could not switch to ${profile.name}: ${error.message ?? String(error)}`,
    );
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
        appendLog("warning", "ui", `${key} refused: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-log-level]").forEach((input) => {
    input.addEventListener("change", async (event) => {
      const previous = state.logLevel;
      state.logLevel = event.currentTarget.value;
      try {
        const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
        applyPersistedSettings(snapshot);
        try {
          await invoke("set_log_level", { level: state.logLevel });
          appendLog("info", "settings", `Clash log level applied: ${state.logLevel}`);
        } catch (error) {
          state.controllerStatus = "controller offline";
          appendLog("warning", "settings", `Log level saved; controller apply failed: ${error.message ?? String(error)}`);
        }
      } catch (error) {
        state.logLevel = previous;
        appendLog("error", "settings", `Log level refused: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-mixed-port]").forEach((input) => {
    input.addEventListener("change", () => {
      handleAction("save-mixed-port").catch((error) => {
        appendLog("error", "settings", error.message ?? String(error));
        renderPage();
      });
    });
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.currentTarget.blur();
      }
    });
  });

  document.querySelectorAll("[data-random-mixed-port]").forEach((input) => {
    input.addEventListener("change", async (event) => {
      try {
        const snapshot = await invoke("write_settings_snapshot", {
          settings: {
            ...persistedSettingsFromUi(),
            randomMixedPort: event.currentTarget.checked,
          },
        });
        applyPersistedSettings(snapshot);
        appendLog("info", "settings", `Random mixed-port ${event.currentTarget.checked ? "enabled" : "disabled"}`);
      } catch (error) {
        appendLog("error", "settings", `Random mixed-port refused: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-core-kind]").forEach((input) => {
    input.addEventListener("change", async (event) => {
      const value = event.currentTarget.value || "mihomo";
      try {
        const snapshot = await invoke("write_settings_snapshot", {
          settings: {
            ...persistedSettingsFromUi(),
            coreKind: value,
            core_kind: value,
          },
        });
        applyPersistedSettings(snapshot);
        appendLog(
          "info",
          "core",
          value === "mihomo"
            ? "Preferred core set to mihomo (manual override)"
            : "Preferred core set to clash-rs (default)",
        );
      } catch (error) {
        appendLog("error", "settings", `Core kind refused: ${error.message ?? String(error)}`);
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
        appendLog("error", "profile", error.message ?? String(error));
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
      const previous = state.mode;
      state.mode = event.currentTarget.dataset.mode;
      try {
        await invoke("set_proxy_mode", { mode: state.mode });
        const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
        applyPersistedSettings(snapshot);
        appendLog("info", "mode", `Proxy mode switched to ${state.mode}`);
        if (state.toggles.breakOnProxyChange) {
          await closeConnectionsAfterProxyChange("mode");
        }
      } catch (error) {
        state.mode = previous;
        state.controllerStatus = "controller offline";
        appendLog("warning", "mode", `Proxy mode refused by controller: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-group][data-node]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const group = state.proxyGroups.find((item) => item.name === event.currentTarget.dataset.group);
      if (!group) return;
      const previous = group.now;
      group.now = event.currentTarget.dataset.node;
      try {
        await invoke("select_proxy", { group: group.name, proxy: group.now });
        appendLog("info", "proxy", `Proxy group ${group.name} switched to ${group.now}`);
        if (state.toggles.breakOnProxyChange) {
          await closeConnectionsAfterProxyChange(group.name);
        }
      } catch (error) {
        group.now = previous;
        state.controllerStatus = "controller offline";
        appendLog("warning", "proxy", `Proxy selection refused: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-profile]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      const id = event.currentTarget.dataset.profile;
      try {
        await selectProfileById(id);
      } catch (error) {
        appendLog("error", "profile", `Profile switch failed: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-update-profile]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const profile = state.profiles.find((item) => item.id === event.currentTarget.dataset.updateProfile);
      if (!profile) return;
      if (!profile.sourceUrl) {
        appendLog("warning", "profile", `${profile.name} is a local profile; use Import File again to replace it`);
        renderPage();
        return;
      }
      const wasActive = profile.active;
      try {
        const result = await invoke("update_profile", { id: profile.id });
        await loadProfilesSnapshot();
        if (wasActive) await invoke("apply_active_profile");
        appendLog("info", "profile", `${result.name} subscription updated${wasActive ? " and config.yaml reapplied" : ""}`);
      } catch (error) {
        appendLog("error", "profile", `Update failed for ${profile.name}: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-reveal-profile]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const id = event.currentTarget.dataset.revealProfile;
      try {
        await invoke("reveal_profile", { id });
        appendLog("info", "profile", `Profile revealed in Finder: ${id}`);
      } catch (error) {
        appendLog("warning", "profile", `Show in Finder failed: ${error.message ?? String(error)}`);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-delete-profile]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const id = event.currentTarget.dataset.deleteProfile;
      try {
        await runProfileMenuAction("delete", id);
      } catch (error) {
        appendLog("error", "profile", `Delete failed: ${error.message ?? String(error)}`);
      }
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
        appendLog("error", "profile", `${action} failed for ${id}: ${error.message ?? String(error)}`);
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
      state.providerActions.add(actionKey);
      renderPage();
      try {
        if (proxyProvider) {
          await invoke("update_proxy_provider", { name: proxyProvider });
        } else {
          await invoke("update_rule_provider", { name: ruleProvider });
        }
        await loadProvidersSnapshot();
        appendLog("info", "provider", `${name} update requested through Clash controller`);
      } catch (error) {
        state.controllerStatus = "controller offline";
        appendLog("warning", "provider", `${name} update failed: ${error.message ?? String(error)}`);
      } finally {
        state.providerActions.delete(actionKey);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-provider-health]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      const name = event.currentTarget.dataset.providerHealth;
      const actionKey = providerActionKey("proxy-health", name);
      state.providerActions.add(actionKey);
      renderPage();
      try {
        await invoke("health_check_proxy_provider", { name });
        await loadProvidersSnapshot();
        appendLog("info", "provider", `${name} health check requested through Clash controller`);
      } catch (error) {
        state.controllerStatus = "controller offline";
        appendLog("warning", "provider", `${name} health check failed: ${error.message ?? String(error)}`);
      } finally {
        state.providerActions.delete(actionKey);
      }
      renderPage();
    });
  });

  document.querySelectorAll("[data-log-filter]").forEach((button) => {
    button.addEventListener("click", (event) => {
      state.logFilter = event.currentTarget.dataset.logFilter;
      renderPage();
    });
  });

  const logSearch = document.querySelector("[data-log-search]");
  if (logSearch) {
    logSearch.addEventListener("input", (event) => {
      state.logSearch = event.currentTarget.value;
      renderPage();
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
      state.closingConnectionIds.add(id);
      renderPage();
      try {
        await invoke("close_connection", { id });
        await loadControllerSnapshot();
        appendLog("info", "connection", `Connection ${id} closed`);
      } catch (error) {
        state.controllerStatus = "controller offline";
        appendLog("warning", "connection", `Controller close failed for ${id}: ${error.message ?? String(error)}`);
      } finally {
        state.closingConnectionIds.delete(id);
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
    const target = eventTarget?.closest("[data-action]");
    if (!target) return;
    event.preventDefault();
    event.stopPropagation();
    handleAction(target.dataset.action).catch((error) => {
      appendLog("error", "ui", error.message ?? String(error));
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
      g: () => handleTrayAction("mode:Global"),
      r: () => handleTrayAction("mode:Rule"),
      d: () => handleTrayAction("mode:Direct"),
      p: () => applyToggle("systemProxy", !state.toggles.systemProxy, "shortcut"),
      t: () => applyToggle("tunMode", !state.toggles.tunMode, "shortcut"),
      m: () => applyToggle("mixin", !state.toggles.mixin, "shortcut"),
      s: () => handleAction("save-settings"),
    }[key];
    if (shortcutAction) {
      event.preventDefault();
      shortcutAction().catch((error) => {
        appendLog("warning", "shortcut", error.message ?? String(error));
        renderPage();
      });
    }
  });
}

async function applyToggle(key, checked, source) {
  const previous = state.toggles[key];
  state.toggles[key] = checked;
  try {
    if (key === "systemProxy") {
      const snapshot = await invoke("set_system_proxy_enabled", { enabled: checked });
      applyPersistedSettings(snapshot);
      // System Proxy must never flip TUN; re-sync runtime truth after settings write.
      await loadTunRuntimeState();
      await loadNetworkDiagnostics();
    } else if (key === "tunMode") {
      if (checked && state.serviceModeStatus !== "Enabled") {
        state.toggles[key] = previous;
        state.glassDialog = {
          kind: "info",
          payload: { title: "TUN Mode", body: "To enable this mode, please install Service Mode first!" },
        };
        renderGlassOverlays();
        return;
      }
      const snapshot = await invoke("set_tun_enabled", { enabled: checked });
      applyPersistedSettings(snapshot);
      await loadTunRuntimeState();
      await loadCoreStatus();
      await loadControllerSnapshotWithRetry(checked ? 12 : 6, 500);
    } else if (key === "mixin") {
      const snapshot = await invoke("write_settings_snapshot", { settings: { ...persistedSettingsFromUi(), mixin: checked } });
      applyPersistedSettings(snapshot);
      if (activeProfile().active) {
        const applied = await invoke("apply_active_profile");
        appendLog("info", source, `Mixin ${checked ? "enabled" : "disabled"}; active config reapplied (${formatBytes(applied.bytes ?? 0)})`);
      }
    } else if (key === "startAtLogin") {
      const snapshot = await invoke("set_launch_at_login_enabled", { enabled: checked });
      applyPersistedSettings(snapshot);
    } else if (key === "allowLan") {
      const snapshot = await invoke("set_allow_lan", { enabled: checked });
      applyPersistedSettings(snapshot);
    } else if (key === "enableIpv6") {
      const snapshot = await invoke("set_ipv6", { enabled: checked });
      applyPersistedSettings(snapshot);
    } else {
      const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
      applyPersistedSettings(snapshot);
      if (key === "usePacScript" && state.toggles.systemProxy) {
        const refreshed = await invoke("set_system_proxy_enabled", { enabled: true });
        applyPersistedSettings(refreshed);
        await loadNetworkDiagnostics();
      }
    }
    appendLog("info", source, `${key} changed to ${checked ? "on" : "off"}`);
  } catch (error) {
    state.toggles[key] = previous;
    if (key === "tunMode") {
      try {
        await loadSettingsSnapshot();
      } catch (_reloadError) {
        /* keep local previous */
      }
    }
    throw error;
  }
}

async function handleAction(action) {
  if (action === "open-settings") {
    state.activePage = "settings";
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
    const count = state.connections.length;
    try {
      await invoke("close_all_connections");
      appendLog("warning", "proxy", `Broke ${count} connection(s)`);
      await loadControllerSnapshot();
    } catch (error) {
      appendLog("warning", "proxy", `Break connections failed: ${error.message ?? String(error)}`);
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
    const count = state.connections.length;
    state.closingAllConnections = true;
    renderPage();
    try {
      await invoke("close_all_connections");
      appendLog("warning", "connection", `Closed ${count} active connections`);
      await loadControllerSnapshot();
    } catch (error) {
      state.controllerStatus = "controller offline";
      appendLog("warning", "connection", `Controller close-all failed; keeping local rows: ${error.message ?? String(error)}`);
    } finally {
      state.closingAllConnections = false;
    }
  }
  if (action === "delay-test") {
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
    } else if (tauriApi()?.core?.invoke) {
      const generation = (runtime.delayTestGeneration = (runtime.delayTestGeneration ?? 0) + 1);
      state.toggles.testingDelays = true;
      if (activeGroup) {
        activeGroup.options.forEach((node) => {
          if (names.includes(node.name)) {
            node.delay = null;
            node.dead = false;
          }
        });
      }
      patchProxyDelayLabels(names);
      try {
        const delayUrl = state.settingsSnapshot?.settings?.delayTestUrl
          ?? state.settingsSnapshot?.settings?.delay_test_url
          ?? null;
        const delayByName = new Map();
        let offset = 0;
        while (offset < names.length) {
          if (generation !== runtime.delayTestGeneration) break;
          const concurrency = delayConcurrency();
          const chunk = names.slice(offset, offset + concurrency);
          offset += chunk.length;
          const results = await invoke("test_proxy_delays", {
            proxies: chunk,
            url: delayUrl,
            timeout_ms: 5000,
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
              // timeout (0), missing delay, or error → Timeout
              delayByName.set(item.name, 0);
              applyDelayToProxyNodes(item.name, 0);
            }
          }
          for (const name of chunk) {
            if (!seen.has(name) && !delayByName.has(name)) {
              delayByName.set(name, 0);
              applyDelayToProxyNodes(name, 0);
            }
          }
          patchProxyDelayLabels(chunk);
        }
        if (generation === runtime.delayTestGeneration) {
          finalizeDelayTestNames(names);
          const failed = [...delayByName.values()].filter((delay) => delay <= 0).length
            + names.filter((name) => !delayByName.has(name)).length;
          const ok = [...delayByName.values()].filter((delay) => delay > 0).length;
          appendLog(
            failed ? "warning" : "info",
            "proxy",
            `Delay test (${activeGroup?.name ?? "group"}): ${ok} ok${failed ? `, ${failed} timed out` : ""} · concurrency ${delayConcurrency()}`,
          );
        }
      } catch (error) {
        if ((runtime.delayTestGeneration ?? 0) === generation) {
          finalizeDelayTestNames(names);
          appendLog("warning", "proxy", `Delay test failed: ${error.message ?? String(error)}`);
        }
      } finally {
        if ((runtime.delayTestGeneration ?? 0) === generation) {
          state.toggles.testingDelays = false;
          patchProxyDelayLabels(names);
        }
      }
    } else {
      state.proxyGroups.forEach((group) => {
        group.options.forEach((node, index) => {
          if (node.delay > 0) node.delay = Math.max(18, node.delay + ((index % 2 === 0) ? -5 : 7));
        });
      });
      appendLog("info", "proxy", "Delay test completed in preview mode");
    }
  }
  if (action === "reload-proxies") {
    const live = await loadControllerSnapshot();
    appendLog(live ? "info" : "warning", "proxy", live ? "Controller snapshot reloaded" : "Controller unavailable; keeping local data");
  }
  if (action === "start-core") {
    try {
      state.coreStatus = await invoke("start_core");
      if (state.coreStatus?.state === "Running") {
        state.coreStartedAt = Date.now();
        state.traffic.runtimeSeconds = 0;
        updateStatusBar();
      }
      appendLog("info", "core", state.coreStatus.message);
      await loadControllerSnapshot();
    } catch (error) {
      state.coreStatus = await invoke("core_status");
      appendLog("error", "core", error.message ?? String(error));
    }
  }
  if (action === "install-pinned-core" || action === "install-latest-core") {
    try {
      appendLog("info", "core", "Installing pinned darwin-arm64 Mihomo core package...");
      const result = await invoke("install_pinned_mihomo_core");
      state.coreStatus = await invoke("core_status");
      appendLog("info", "core", `Pinned core installed: ${formatBytes(result.bytes ?? 0)} · ${String(result.sha256 ?? "").slice(0, 12)}`);
    } catch (error) {
      appendLog("error", "core", `Core install failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "install-pinned-clash-rs") {
    try {
      appendLog("info", "core", "Installing pinned clash-rs aarch64 (does not change default core)...");
      const result = await invoke("install_pinned_clash_rs_core");
      appendLog(
        "info",
        "core",
        `Pinned clash-rs installed: ${formatBytes(result.bytes ?? 0)} · ${String(result.sha256 ?? "").slice(0, 12)}`,
      );
    } catch (error) {
      appendLog("error", "core", `clash-rs install failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "stop-core") {
    try {
      state.coreStatus = await invoke("stop_core");
      state.coreStartedAt = null;
      state.traffic.runtimeSeconds = 0;
      updateStatusBar();
      appendLog("warning", "core", state.coreStatus.message);
    } catch (error) {
      appendLog("error", "core", error.message ?? String(error));
    }
  }
  if (action === "copy-proxy-exports") {
    const port = state.settingsSnapshot?.settings?.mixed_port ?? 7890;
    const exports = [
      `export https_proxy=http://127.0.0.1:${port}`,
      `export http_proxy=http://127.0.0.1:${port}`,
      `export all_proxy=socks5://127.0.0.1:${port}`,
    ].join("\n");
    try {
      await navigator.clipboard.writeText(exports);
      appendLog("info", "shell", "Copied proxy export commands for Terminal");
    } catch (error) {
      appendLog("warning", "clipboard", error.message ?? String(error));
    }
  }
  if (action === "toggle-random-mixed-port") {
    const current = Boolean(state.settingsSnapshot?.settings?.randomMixedPort ?? state.settingsSnapshot?.settings?.random_mixed_port);
    try {
      const snapshot = await invoke("write_settings_snapshot", {
        settings: { ...persistedSettingsFromUi(), randomMixedPort: !current, random_mixed_port: !current },
      });
      applyPersistedSettings(snapshot);
      appendLog("info", "settings", `Random mixed-port ${!current ? "enabled" : "disabled"}`);
    } catch (error) {
      appendLog("warning", "settings", error.message ?? String(error));
    }
  }
  if (action === "allow-lan-info") {
    state.glassDialog = {
      kind: "info",
      payload: {
        title: "Allow LAN",
        body: "Turn on to listen on all interfaces by default, or else only listen on 127.0.0.1. You can change the Bind Address on the right to specify a particular interface.",
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
        kind: "network-interfaces",
        payload: diagnostics?.services ?? [],
        defaultRoute: diagnostics?.default_route_interface ?? diagnostics?.defaultRouteInterface ?? "unknown",
      };
      renderGlassOverlays();
      return;
    } catch (error) {
      appendLog("warning", "network", error.message ?? String(error));
    }
  }
  if (action === "edit-bind-address") {
    const persisted = state.settingsSnapshot?.settings ?? {};
    state.glassDialog = { kind: "bind-address", payload: bindAddressLabel(persisted) };
    renderGlassOverlays();
    return;
  }
  if (action === "preview-runtime-config") {
    try {
      const body = await invoke("read_runtime_config_text");
      state.glassDialog = { kind: "preview-config", payload: body };
      renderGlassOverlays();
      return;
    } catch (error) {
      appendLog("warning", "core", `Config preview failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "dns-query") {
    state.glassDialog = { kind: "dns-query", payload: { name: "www.gstatic.com", type: "A", result: "" } };
    renderGlassOverlays();
    return;
  }
  if (action === "script-test") {
    state.glassDialog = { kind: "script-test" };
    renderGlassOverlays();
    return;
  }
  if (action === "open-controller-dashboard") {
    const settings = state.settingsSnapshot?.settings ?? {};
    const host = settings.external_controller_host ?? "127.0.0.1";
    const port = settings.external_controller_port ?? 9090;
    const secret = settings.secret ? encodeURIComponent(settings.secret) : "";
    const url = `https://clash.razord.top/#/?host=${encodeURIComponent(host)}&port=${port}${secret ? `&secret=${secret}` : ""}`;
    try {
      await invoke("open_external_url", { url });
      appendLog("info", "core", `Opened controller dashboard (${host}:${port})`);
    } catch (error) {
      try {
        await navigator.clipboard.writeText(url);
        appendLog("warning", "core", `Open failed; URL copied instead: ${error.message ?? String(error)}`);
      } catch (clipError) {
        appendLog("info", "core", url);
        appendLog("warning", "core", error.message ?? String(error));
        appendLog("warning", "clipboard", clipError.message ?? String(clipError));
      }
    }
    return;
  }
  if (action === "tun-info") {
    state.glassDialog = {
      kind: "info",
      payload: { title: "TUN Mode", body: "To enable this mode, please install Service Mode first!" },
    };
    renderGlassOverlays();
    return;
  }
  if (action === "tun-settings") {
    const settings = state.settingsSnapshot?.settings ?? {};
    state.glassDialog = {
      kind: "tun-settings",
      payload: {
        stack: settings["tun-stack"] ?? settings.tunStack ?? "mixed",
        autoRoute: settings["tun-auto-route"] ?? settings.tunAutoRoute ?? true,
        strictRoute: settings["tun-strict-route"] ?? settings.tunStrictRoute ?? true,
        dnsHijack: settings["tun-dns-hijack"] ?? settings.tunDnsHijack ?? "any:53\n[::]:53",
      },
    };
    renderGlassOverlays();
    return;
  }
  if (action === "tun-reset-dns") {
    const settings = state.settingsSnapshot?.settings ?? {};
    state.glassDialog = {
      kind: "tun-reset-dns",
      payload: settings["restore-dns-servers"] ?? settings.restoreDnsServers ?? "Empty",
    };
    renderGlassOverlays();
    return;
  }
  if (action === "mixin-info") {
    state.glassDialog = {
      kind: "info",
      payload: {
        title: "Mixin",
        body: "When Mixin is enabled, YAML is recursively merged into the generated config.yaml before the core reloads.",
      },
    };
    renderGlassOverlays();
    return;
  }
  if (action === "edit-mixin") {
    const settings = state.settingsSnapshot?.settings ?? {};
    state.glassDialog = {
      kind: "edit-mixin",
      payload: settings.mixin_yaml ?? settings.mixinYaml ?? state.mixinYaml ?? "",
    };
    renderGlassOverlays();
    return;
  }
  if (action === "open-home-directory") {
    try {
      await invoke("reveal_home_directory");
      appendLog("info", "shell", "Home Directory opened in Finder");
    } catch (error) {
      appendLog("warning", "shell", `Open Folder failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "save-mixed-port") {
    const input = document.querySelector("[data-mixed-port]");
    const port = Number.parseInt(input?.value ?? "", 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      appendLog("error", "settings", "mixed-port must be between 1 and 65535");
    } else {
      const previousPort = state.settingsSnapshot?.settings?.mixed_port ?? fallbackSettingsSnapshot.settings.mixed_port;
      try {
        const snapshot = await invoke("write_settings_snapshot", { settings: { ...persistedSettingsFromUi(), mixed_port: port } });
        applyPersistedSettings(snapshot);
        if (activeProfile().active) {
          await invoke("apply_active_profile");
        }
        if (state.toggles.systemProxy) {
          const proxySnapshot = await invoke("set_system_proxy_enabled", { enabled: true });
          applyPersistedSettings(proxySnapshot);
        }
        appendLog("info", "settings", `mixed-port saved: ${port}${state.coreStatus?.state === "Running" ? "; restart core to guarantee full reload" : ""}`);
      } catch (error) {
        const rollback = await invoke("write_settings_snapshot", { settings: { ...persistedSettingsFromUi(), mixed_port: previousPort } });
        applyPersistedSettings(rollback);
        appendLog("error", "settings", `mixed-port refused: ${error.message ?? String(error)}`);
      }
    }
  }
  if (action === "import-profile") {
    const input = document.querySelector("[data-profile-url]");
    const url = input?.value?.trim();
    if (!url) {
      appendLog("warning", "profile", "Profile URL is required before download");
    } else {
      const previousActiveProfile = activeProfile().active ? activeProfile().id : null;
      const result = await invoke("import_profile_url", { url, name: null, activate: true });
      await loadProfilesSnapshot();
      try {
        const applied = await invoke("apply_active_profile");
        appendLog("info", "profile", `Remote profile imported and applied: ${result.name} (${formatBytes(applied.bytes ?? result.bytes ?? 0)})`);
      } catch (error) {
        const rollback = await invoke("write_settings_snapshot", { settings: { ...persistedSettingsFromUi(), active_profile: previousActiveProfile } });
        applyPersistedSettings(rollback);
        await loadProfilesSnapshot();
        appendLog("error", "profile", `Remote profile imported, but config apply failed: ${error.message ?? String(error)}`);
      }
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
    } else {
      const previousActiveProfile = activeProfile().active ? activeProfile().id : null;
      const body = await file.text();
      const result = await invoke("import_profile_text", { name: file.name, body, activate: true });
      await loadProfilesSnapshot();
      try {
        const applied = await invoke("apply_active_profile");
        appendLog("info", "profile", `Local profile imported and applied: ${result.name} (${formatBytes(applied.bytes ?? result.bytes ?? 0)})`);
      } catch (error) {
        const rollback = await invoke("write_settings_snapshot", { settings: { ...persistedSettingsFromUi(), active_profile: previousActiveProfile } });
        applyPersistedSettings(rollback);
        await loadProfilesSnapshot();
        appendLog("error", "profile", `Local profile imported, but config apply failed: ${error.message ?? String(error)}`);
      } finally {
        if (input) input.value = "";
      }
    }
  }
  if (action === "migrate-legacy-profiles") {
    const imported = await invoke("migrate_legacy_cfw_profiles");
    await loadProfilesSnapshot();
    if (activeProfile().active) {
      try {
        const applied = await invoke("apply_active_profile");
        appendLog("info", "profile", `Migrated ${imported.length} CFW profile(s); active config applied (${formatBytes(applied.bytes ?? 0)})`);
      } catch (error) {
        appendLog("warning", "profile", `Migrated ${imported.length} CFW profile(s), but active config apply failed: ${error.message ?? String(error)}`);
      }
    } else {
      appendLog("info", "profile", `Migrated ${imported.length} CFW profile(s)`);
    }
  }
  if (action === "update-all-profiles") {
    const remoteProfiles = state.profiles.filter((profile) => profile.sourceUrl);
    let updated = 0;
    let failed = 0;
    for (const profile of remoteProfiles) {
      try {
        await invoke("update_profile", { id: profile.id });
        updated += 1;
      } catch (error) {
        failed += 1;
        appendLog("warning", "profile", `Update failed for ${profile.name}: ${error.message ?? String(error)}`);
      }
    }
    await loadProfilesSnapshot();
    if (activeProfile().active) {
      try {
        await invoke("apply_active_profile");
      } catch (error) {
        appendLog("warning", "profile", `Active profile reapply failed: ${error.message ?? String(error)}`);
      }
    }
    appendLog(failed ? "warning" : "info", "profile", `Update All profiles completed: ${updated} updated${failed ? `, ${failed} failed` : ""}`);
  }
  if (action === "save-profile-editor") {
    const editor = document.querySelector("[data-profile-editor]");
    const inspector = state.profileInspector;
    if (!editor || !inspector?.profile?.id) {
      appendLog("warning", "profile", "No profile editor is open");
    } else {
      const result = await invoke("save_profile_text", { id: inspector.profile.id, body: editor.value });
      if (result.active) {
        await invoke("apply_active_profile");
      }
      await loadProfilesSnapshot();
      await openProfileInspector(result.id, "edit");
      appendLog("info", "profile", `Profile YAML saved${result.active ? " and active config hot-reloaded" : ""}: ${formatBytes(result.bytes ?? 0)}`);
    }
  }
  if (action === "close-profile-inspector") {
    state.profileInspector = null;
  }
  if (action === "update-all-providers") {
    state.providerBulkActions.add(action);
    renderPage();
    try {
      const [proxyOutcome, ruleOutcome] = await Promise.allSettled([
        invoke("update_all_proxy_providers"),
        invoke("update_all_rule_providers"),
      ]);
      const proxyProviders = proxyOutcome.status === "fulfilled" ? proxyOutcome.value : emptyProviderBatch("update-proxy");
      const ruleProviders = ruleOutcome.status === "fulfilled" ? ruleOutcome.value : emptyProviderBatch("update-rule");
      if (proxyOutcome.status === "rejected") appendLog("warning", "provider", `Proxy provider list failed: ${proxyOutcome.reason?.message ?? String(proxyOutcome.reason)}`);
      if (ruleOutcome.status === "rejected") appendLog("warning", "provider", `Rule provider list failed: ${ruleOutcome.reason?.message ?? String(ruleOutcome.reason)}`);
      await loadProvidersSnapshot();
      const proxySummary = providerBatchSummary("Proxy providers", proxyProviders);
      const ruleSummary = providerBatchSummary("Rule providers", ruleProviders);
      const level = providerBatchSucceeded(proxyProviders) && providerBatchSucceeded(ruleProviders) && proxyOutcome.status === "fulfilled" && ruleOutcome.status === "fulfilled" ? "info" : "warning";
      appendLog(level, "provider", `Update All completed · ${proxySummary} · ${ruleSummary}`);
    } catch (error) {
      state.controllerStatus = "controller offline";
      appendLog("warning", "provider", `Update All failed: ${error.message ?? String(error)}`);
    } finally {
      state.providerBulkActions.delete(action);
      renderPage();
    }
  }
  if (action === "health-check-all") {
    state.providerBulkActions.add(action);
    renderPage();
    try {
      const proxyProviders = await invoke("health_check_all_proxy_providers");
      await loadProvidersSnapshot();
      appendLog(providerBatchSucceeded(proxyProviders) ? "info" : "warning", "provider", providerBatchSummary("Health Check All", proxyProviders));
    } catch (error) {
      state.controllerStatus = "controller offline";
      appendLog("warning", "provider", `Health Check All failed: ${error.message ?? String(error)}`);
    } finally {
      state.providerBulkActions.delete(action);
      renderPage();
    }
  }
  if (action === "flush-fake-ip-cache") {
    try {
      await invoke("flush_fake_ip_cache");
      appendLog("info", "cache", "Fake IP cache flushed through Clash controller");
    } catch (error) {
      state.controllerStatus = "controller offline";
      appendLog("warning", "cache", `Fake IP cache flush failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "reload-rules") {
    const loaded = await loadRulesSnapshot();
    appendLog(loaded ? "info" : "warning", "rules", loaded ? `Loaded ${state.rules.length} controller rules` : "Rules controller endpoint unavailable");
  }
  if (action === "toggle-log-stream") {
    state.logsPaused = !state.logsPaused;
    appendLog("info", "logs", `Request logs ${state.logsPaused ? "paused" : "resumed"}`);
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
      appendLog("warning", "logs", `Copy logs refused: ${error.message ?? String(error)}`);
    }
  }
  if (action === "reveal-logs") {
    try {
      await invoke("reveal_logs_directory");
      appendLog("info", "logs", "Logs folder opened in Finder");
    } catch (error) {
      appendLog("warning", "logs", `Open Folder failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "toggle-connection-stream") {
    state.connectionPaused = !state.connectionPaused;
    appendLog("info", "connections", `Connection view ${state.connectionPaused ? "frozen" : "unfrozen"}`);
  }
  if (action === "close-connection-detail") {
    state.connectionDetailId = null;
  }
  if (action === "clear-connection-search") {
    state.connectionSearch = "";
  }
  if (action === "clear-deep-links") {
    state.deepLinks = [];
  }
  if (action === "save-settings") {
    const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
    applyPersistedSettings(snapshot);
    if (state.toggles.systemProxy) {
      const refreshed = await invoke("set_system_proxy_enabled", { enabled: true });
      applyPersistedSettings(refreshed);
      await loadNetworkDiagnostics();
    }
    if (activeProfile().active) {
      const applied = await invoke("apply_active_profile");
      appendLog("info", "settings", `cfw-settings.yaml saved; active config reapplied (${formatBytes(applied.bytes ?? 0)})`);
    } else {
      appendLog("info", "settings", "cfw-settings.yaml saved");
    }
  }
  if (action === "check-for-updates") {
    try {
      openProductAboutDialog({ autoCheck: true, checking: true });
      const result = await invoke("check_for_updates");
      await promptInstallUpdate(result);
    } catch (error) {
      appendLog("warning", "updater", `Update check failed: ${error.message ?? String(error)}`);
      openProductAboutDialog({
        autoCheck: true,
        checking: false,
        result: { available: false, error: error.message ?? String(error), current: state.payload?.product?.version },
      });
    }
  }
  if (action === "load-kernel-compare" || action === "show-kernel-compare") {
    const report = await loadKernelCompare(action === "load-kernel-compare");
    if (!report?.comparison) {
      appendLog("warning", "bench", "No measured kernel compare report found");
      return;
    }
    const n = report.comparison.narrative ?? {};
    const h = report.comparison.headline ?? {};
    window.alert(
      [
        `Measured clash-rs vs mihomo (${report.measured_at ?? "local"})`,
        "",
        n.speed ?? "",
        n.stability ?? "",
        n.weak_net ?? "",
        "",
        `Headline: cold ${h.cold_start_speedup_x ?? "n/a"}× · API ${h.controller_api_speedup_x ?? "n/a"}× · weak-net ${h.weak_net_success_delta_pp ?? "n/a"} pp`,
        "Not a CFW 3× claim — same-machine core-vs-core only.",
      ].join("\n"),
    );
    renderPage();
  }
  if (action === "reload-settings") {
    await loadSettingsSnapshot();
    appendLog("info", "settings", "cfw-settings.yaml reloaded");
  }
  if (action === "manage-service-mode") {
    state.glassDialog = { kind: "service-mode-manage" };
    renderGlassOverlays();
    return;
  }
  if (action === "update-geoip-database") {
    if (state.geoipUpdating) return;
    // WKWebView often swallows window.prompt — use in-app glass dialog.
    state.glassDialog = { kind: "geoip" };
    renderGlassOverlays();
    return;
  }
  if (action === "install-helper-service") {
    try {
      const snapshot = await invoke("install_helper_service");
      applyPersistedSettings(snapshot);
      appendLog("info", "helper", "Privileged helper installed through launchd");
    } catch (error) {
      appendLog("warning", "helper", `Helper install needs administrator context: ${error.message ?? String(error)}`);
    }
  }
  if (action === "uninstall-helper-service") {
    try {
      const snapshot = await invoke("uninstall_helper_service");
      applyPersistedSettings(snapshot);
      appendLog("info", "helper", "Privileged helper removed from launchd");
    } catch (error) {
      appendLog("warning", "helper", `Helper uninstall failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "run-tray-script") {
    const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
    applyPersistedSettings(snapshot);
    try {
      const result = await invoke("run_tray_script");
      const details = [result.stdout, result.stderr].filter(Boolean).join(" · ");
      appendLog(result.status === 0 ? "info" : "warning", "action", `Tray Script exited ${result.status ?? "unknown"}${details ? ` · ${details}` : ""}`);
    } catch (error) {
      appendLog("warning", "action", `Tray Script failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "run-child-process") {
    const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
    applyPersistedSettings(snapshot);
    try {
      const result = await invoke("run_child_process");
      const details = [result.stdout, result.stderr].filter(Boolean).join(" · ");
      appendLog(result.status === 0 ? "info" : "warning", "action", `Child Process exited ${result.status ?? "unknown"}${details ? ` · ${details}` : ""}`);
    } catch (error) {
      appendLog("warning", "action", `Child Process failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "reset-settings") {
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

async function handleTrayAction(action) {
  if (action?.startsWith("proxy-select:")) {
    const [, encodedGroup, encodedProxy] = action.split(":");
    const groupName = decodeURIComponent(encodedGroup ?? "");
    const proxyName = decodeURIComponent(encodedProxy ?? "");
    const group = state.proxyGroups.find((item) => item.name === groupName);
    if (group && proxyName) {
      const previous = group.now;
      group.now = proxyName;
      try {
        await invoke("select_proxy", { group: groupName, proxy: proxyName });
        appendLog("info", "tray", `Proxy group ${groupName} switched to ${proxyName}`);
        if (state.toggles.breakOnProxyChange) {
          await closeConnectionsAfterProxyChange(groupName);
        }
      } catch (error) {
        group.now = previous;
        appendLog("warning", "tray", `Tray proxy selection failed: ${error.message ?? String(error)}`);
      }
    }
  }

  if (action?.startsWith("mode:")) {
    const mode = action.split(":")[1];
    if (["Global", "Rule", "Direct", "Script"].includes(mode)) {
      const previous = state.mode;
      state.mode = mode;
      try {
        await invoke("set_proxy_mode", { mode });
        const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
        applyPersistedSettings(snapshot);
        appendLog("info", "tray", `Proxy mode switched to ${mode}`);
        if (state.toggles.breakOnProxyChange) {
          await closeConnectionsAfterProxyChange("tray mode");
        }
      } catch (error) {
        state.mode = previous;
        appendLog("warning", "tray", `Mode switch failed: ${error.message ?? String(error)}`);
      }
    }
  }

  if (action === "toggle-system-proxy") {
    await applyToggle("systemProxy", !state.toggles.systemProxy, "tray");
  }
  if (action === "toggle-tun-mode") {
    await applyToggle("tunMode", !state.toggles.tunMode, "tray");
  }
  if (action === "toggle-mixin") {
    await applyToggle("mixin", !state.toggles.mixin, "tray");
  }
  if (action === "close-all") {
    await handleAction("close-all");
    return;
  }
  if (action === "restart-core") {
    await handleAction("stop-core");
    await handleAction("start-core");
    return;
  }
  if (action === "run-tray-script") {
    try {
      const result = await invoke("run_tray_script");
      const details = [result.stdout, result.stderr].filter(Boolean).join(" · ");
      appendLog(result.status === 0 ? "info" : "warning", "tray", `Tray Script exited ${result.status ?? "unknown"}${details ? ` · ${details}` : ""}`);
    } catch (error) {
      appendLog("warning", "tray", `Tray Script failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "toggle-devtools") {
    try {
      await invoke("toggle_devtools");
      appendLog("info", "tray", "DevTools toggled");
    } catch (error) {
      appendLog("warning", "tray", error.message ?? String(error));
    }
  }
  if (action === "move-dashboard") {
    await invoke("move_dashboard_to_nearest_monitor");
    appendLog("info", "tray", "Dashboard moved to the active monitor");
  }

  renderPage();
}

function appendLog(level, source, message) {
  const now = new Date();
  state.logs.unshift({
    time: now.toTimeString().slice(0, 8),
    level: normalizeLevel(level),
    source,
    message,
    fields: [],
  });
  state.logs = state.logs.slice(0, MAX_LOG_ROWS);
}

function appendLogLines(lines) {
  const normalized = (lines ?? []).map((line) => ({
    time: line.time ?? "live",
    level: normalizeLevel(line.level),
    source: line.source ?? "core",
    message: line.message ?? "",
    fields: line.fields ?? [],
  }));
  state.logs = [...normalized.reverse(), ...state.logs].slice(0, MAX_LOG_ROWS);
}

async function closeConnectionsAfterProxyChange(reason) {
  const count = state.connections.length;
  if (!count) return;
  try {
    await invoke("close_all_connections");
    state.connections = [];
    state.connectionStream.rows = new Map();
    appendLog("warning", "connection", `Closed ${count} connection(s) after ${reason} switch`);
  } catch (error) {
    state.controllerStatus = "controller offline";
    appendLog("warning", "connection", `Connection cleanup after ${reason} switch failed: ${error.message ?? String(error)}`);
  }
}

async function openProfileInspector(id, mode, focusKey = null) {
  const profile = await invoke("read_profile_text", { id });
  const inspector = { id, mode, profile, focusKey };
  if (mode === "qrcode") {
    try {
      inspector.svg = await invoke("profile_qrcode_svg", { id });
    } catch (error) {
      inspector.error = error.message ?? String(error);
    }
  }
  state.profileInspector = inspector;
}

function focusProfileEditorSection(key) {
  if (!key) return;
  const editor = document.querySelector("[data-profile-editor]");
  if (!(editor instanceof HTMLTextAreaElement)) return;
  const body = editor.value;
  const match = body.match(new RegExp(`^${key}\\s*:`, "im"));
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
  state.payload = await invoke("boot_payload");
  state.lastRefresh = "Just now";
  await loadSettingsSnapshot();
  await loadSystemProxyState();
  await loadNetworkDiagnostics();
  await loadCoreStatus();
  await loadProfilesSnapshot();
  renderPage();
  Promise.all([loadControllerSnapshotWithRetry(), loadProvidersSnapshot()]).finally(() => {
    appendLog("info", "shell", "Boot payload reloaded from Rust");
    renderPage();
  });
}

async function loadSettingsSnapshot() {
  const snapshot = await invoke("read_settings_snapshot");
  applyPersistedSettings(snapshot);
}

async function loadSystemProxyState() {
  try {
    const stateName = await invoke("system_proxy_state");
    state.toggles.systemProxy = stateName === "Enabled";
    if (stateName === "External") {
      appendLog("info", "sysproxy", "macOS has a non-Clash proxy configured; Clash for Mac will not overwrite it unless you enable System Proxy here");
    }
  } catch (error) {
    appendLog("warning", "sysproxy", `Unable to read macOS system proxy: ${error.message ?? String(error)}`);
  }
}

async function loadTunRuntimeState() {
  try {
    state.tunRuntime = await invoke("tun_runtime_state");
    // Only show On when handoff is actually live (utun + managed root core).
    state.toggles.tunMode = Boolean(state.tunRuntime?.active);
  } catch (error) {
    state.tunRuntime = null;
    appendLog("warning", "tun", `Unable to read TUN runtime: ${error.message ?? String(error)}`);
  }
}

async function loadNetworkDiagnostics() {
  try {
    state.networkDiagnostics = await invoke("network_diagnostics");
  } catch (error) {
    state.networkDiagnostics = null;
    appendLog("warning", "network", `Unable to inspect macOS network services: ${error.message ?? String(error)}`);
  }
}

async function loadCoreStatus() {
  const previousState = state.coreStatus?.state;
  try {
    state.coreStatus = await invoke("core_status");
  } catch (error) {
    state.coreStatus = fallbackCoreStatus;
    appendLog("warning", "core", error.message ?? String(error));
  }
  const nextState = state.coreStatus?.state;
  if (nextState === "Running") {
    if (previousState !== "Running" || !state.coreStartedAt) {
      state.coreStartedAt = Date.now();
    }
    state.traffic.runtimeSeconds = Math.floor((Date.now() - state.coreStartedAt) / 1000);
  } else {
    state.coreStartedAt = null;
    state.traffic.runtimeSeconds = 0;
  }
  updateStatusBar();
  try {
    state.serviceModeStatus = await invoke("service_mode_status");
  } catch (_error) {
    state.serviceModeStatus = null;
  }
  try {
    state.geoipStatus = await invoke("geoip_database_status");
  } catch (error) {
    state.geoipStatus = null;
    appendLog("warning", "geoip", `Unable to read GeoIP database: ${error.message ?? String(error)}`);
  }
  if (nextState === "Running") {
    try {
      state.controllerVersion = await invoke("controller_version");
    } catch (_error) {
      state.controllerVersion = null;
    }
  } else {
    state.controllerVersion = null;
  }
}

async function loadControllerSnapshot() {
  try {
    const snapshot = await invoke("controller_snapshot");
    if (!snapshot) {
      clearControllerBackedState();
      state.controllerStatus = "reference preview only";
      return false;
    }
    applyControllerSnapshot(snapshot);
    invoke("refresh_tray_menu").catch((error) => {
      appendLog("warning", "tray", `Tray refresh failed: ${error.message ?? String(error)}`);
    });
    appendLog("info", "controller", "Live controller snapshot applied");
    return true;
  } catch (error) {
    clearControllerBackedState();
    state.controllerStatus = "controller offline";
    appendLog("warning", "controller", error.message ?? String(error));
    return false;
  }
}

async function loadControllerSnapshotWithRetry(attempts = 4, delayMs = 600) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await loadControllerSnapshot()) return true;
    if (attempt + 1 < attempts) await sleep(delayMs);
  }
  return false;
}

function clearControllerBackedState() {
  if (tauriApi()?.core?.invoke) {
    state.proxyGroups = [];
    state.connections = [];
    state.rules = [];
    state.connectionStream.rows = new Map();
  }
}

async function loadProvidersSnapshot() {
  try {
    const snapshot = await invoke("providers_snapshot");
    if (!applyProvidersSnapshot(snapshot)) return false;
    appendLog("info", "provider", "Live providers snapshot applied");
    return true;
  } catch (error) {
    if (tauriApi()?.core?.invoke) {
      state.providers = [];
      state.ruleProviders = [];
    }
    appendLog("warning", "provider", error.message ?? String(error));
    return false;
  }
}

async function loadRulesSnapshot() {
  try {
    const snapshot = await invoke("rules_snapshot");
    const rules = Array.isArray(snapshot?.rules) ? snapshot.rules : [];
    state.rules = rules.map((rule) => ({
      index: String(rule.index ?? ""),
      type: rule.kind ?? rule.type ?? "",
      payload: rule.payload ?? "",
      proxy: rule.proxy ?? "",
      provider: rule.provider ?? "",
      hits: String(rule.extra?.hitCount ?? rule.extra?.hit_count ?? 0),
      size: rule.size ?? -1,
      extra: rule.extra ?? {},
    }));
    appendLog("info", "rules", `Live rules snapshot applied: ${state.rules.length} rules`);
    return true;
  } catch (error) {
    if (tauriApi()?.core?.invoke) state.rules = [];
    appendLog("warning", "rules", error.message ?? String(error));
    return false;
  }
}

async function loadProfilesSnapshot() {
  try {
    const profiles = await invoke("profiles_snapshot");
    if (!Array.isArray(profiles)) return false;
    state.profiles = profiles.map((profile) => ({
      id: profile.id,
      name: profile.name,
      type: profile.source_url ? "Remote" : "Local",
      updated: profile.updated_epoch_secs
        ? formatRelativeUpdated(profile.updated_epoch_secs)
        : "unknown",
      updatedEpochSecs: profile.updated_epoch_secs ?? null,
      rules: profile.rule_count ?? 0,
      traffic: formatBytes(profile.bytes ?? 0),
      active: Boolean(profile.active),
      path: profile.path,
      sourceUrl: profile.source_url ?? null,
      subscriptionUserinfo: profile.subscription_userinfo ?? null,
      updateInterval: profile.update_interval ?? null,
      homeWeb: profile.home_web ?? null,
    }));
    return true;
  } catch (error) {
    state.profiles = [];
    appendLog("warning", "profile", error.message ?? String(error));
    return false;
  }
}

async function startLiveStreams() {
  try {
    await invoke("start_connections_stream");
  } catch (error) {
    appendLog("warning", "connections", `Live stream unavailable: ${error.message ?? String(error)}`);
  }

  try {
    await invoke("start_log_stream");
  } catch (error) {
    appendLog("warning", "logs", `Log stream unavailable: ${error.message ?? String(error)}`);
  }
}

async function processDeepLinks(urls) {
  const outcomes = await invoke("parse_deep_links", { urls });
  for (const outcome of outcomes ?? []) {
    if (outcome.error) {
      appendLog("warning", "protocol", `${outcome.raw || "clash://"} parse failed: ${outcome.error}`);
      continue;
    }

    const intent = outcome.intent;
    if (!intent) continue;
    if (intent.action === "quit") {
      appendLog("warning", "protocol", "clash://quit received");
      await invoke("quit_app");
      continue;
    }

    if ((intent.action === "install-config" || intent.action === "install-profile") && intent.url) {
      try {
        const previousActiveProfile = activeProfile().active ? activeProfile().id : null;
        const result = await invoke("import_profile_url", {
          url: intent.url,
          name: intent.name,
          activate: true,
        });
        await loadProfilesSnapshot();
        try {
          const applied = await invoke("apply_active_profile");
          appendLog("info", "protocol", `${intent.action} imported and applied ${result.name} (${formatBytes(applied.bytes ?? result.bytes ?? 0)})`);
        } catch (error) {
          const rollback = await invoke("write_settings_snapshot", { settings: { ...persistedSettingsFromUi(), active_profile: previousActiveProfile } });
          applyPersistedSettings(rollback);
          await loadProfilesSnapshot();
          throw error;
        }
        await loadSettingsSnapshot();
      } catch (error) {
        appendLog("error", "protocol", `${intent.action} failed: ${error.message ?? String(error)}`);
      }
    } else {
      appendLog("warning", "protocol", `Unsupported clash:// intent ${intent.action}`);
    }
  }
}

async function bootstrap() {
  bindGlobalEvents();
  state.payload = await invoke("boot_payload");
  await loadSettingsSnapshot();
  await loadSystemProxyState();
  await loadTunRuntimeState();
  await loadNetworkDiagnostics();
  await loadCoreStatus();
  await loadProfilesSnapshot();
  await loadKernelCompare().catch(() => null);
  renderPage();
  Promise.all([loadControllerSnapshotWithRetry(), loadProvidersSnapshot()]).finally(renderPage);

  document.getElementById("reload-button").addEventListener("click", reloadPayload);

  await listen("cfw://page", (event) => {
    state.activePage = event.payload;
    renderPage();
  });

  await listen("cfw://settings-changed", async (event) => {
    if (event.payload) applyPersistedSettings(event.payload);
    await loadTunRuntimeState();
    await loadCoreStatus();
    await loadControllerSnapshotWithRetry(8, 400).catch(() => false);
    renderPage();
  });

  await listen("cfw://product-about", (event) => {
    openProductAboutDialog({
      autoCheck: Boolean(event.payload?.auto_check),
      checking: Boolean(event.payload?.checking),
      result: state.updateInfo,
    });
  });

  await listen("cfw://update-available", (event) => {
    applyUpdateInfo(event.payload);
    if (state.glassDialog?.kind === "product-about") {
      openProductAboutDialog({
        autoCheck: true,
        checking: false,
        result: event.payload,
      });
    }
    if (state.activePage === "general" || state.activePage === "settings" || state.activePage === "feedback") {
      renderPage();
    }
  });

  await listen("cfw://menu-check-for-update", async (event) => {
    try {
      if (event.payload?.error) {
        appendLog("warning", "updater", `Update check failed: ${event.payload.error}`);
        applyUpdateInfo(event.payload);
        openProductAboutDialog({ autoCheck: true, checking: false, result: event.payload });
        renderPage();
        return;
      }
      await promptInstallUpdate(event.payload);
    } catch (error) {
      appendLog("warning", "updater", `Update flow failed: ${error.message ?? String(error)}`);
    }
  });

  await listen("cfw://deep-link", (event) => {
    state.deepLinks = Array.isArray(event.payload) ? event.payload : [event.payload];
    if (state.deepLinks.length) {
      appendLog("info", "protocol", `Received ${state.deepLinks.length} clash:// URL(s)`);
      processDeepLinks(state.deepLinks).finally(renderPage);
    } else {
      renderPage();
    }
  });

  await listen("cfw://tray-action", (event) => {
    handleTrayAction(event.payload).catch((error) => {
      appendLog("error", "tray", error.message ?? String(error));
      renderPage();
    });
  });

  await listen("cfw://network-path", (event) => {
    const iface = event.payload?.interface ?? "unknown";
    cancelDelayTest();
    state.proxyGroups.forEach((group) => {
      group.options.forEach((node) => {
        if (typeof node.delay === "number") {
          node.delay = null;
          node.dead = false;
        }
      });
    });
    if (state.activePage === "proxies") {
      patchProxyDelayLabels();
    }
    appendLog("info", "network", `Default route changed (${iface}); delay badges marked stale — re-run Delay Test`);
  });

  await listen("cfw://connections-snapshot", (event) => {
    if (state.connectionPaused) return;
    applyConnectionsSnapshot(event.payload);
    updateStatusBar();
    if (state.activePage === "connections") {
      scheduleConnectionsPatch();
    } else if (state.activePage === "general") {
      scheduleRender();
    }
  });

  await listen("cfw://core-status", (event) => {
    state.coreStatus = event.payload;
    updateStatusBar();
    if (state.activePage === "general") scheduleRender();
  });

  await listen("cfw://log-lines", (event) => {
    if (state.logsPaused) return;
    appendLogLines(event.payload);
    if (state.activePage === "logs") scheduleRender();
  });

  await listen("cfw://stream-error", (event) => {
    const payload = event.payload ?? {};
    appendLog("warning", payload.stream ?? "stream", payload.message ?? "stream unavailable");
    if (state.activePage === "logs" || state.activePage === "connections") scheduleRender();
  });

  await listen("tauri://drag-drop", async (event) => {
    const paths = event.payload?.paths ?? [];
    const yamlPaths = paths.filter((path) => /\.ya?ml$/i.test(path));
    if (!yamlPaths.length) {
      if (paths.length) {
        appendLog("warning", "profile", "Drag-drop ignored: only .yaml/.yml profile files are supported");
      }
      return;
    }
    for (const path of yamlPaths) {
      await importProfileFromPath(path);
    }
  });

  await startLiveStreams();

  window.setInterval(() => {
    if (state.coreStatus?.state === "Running") {
      if (!state.coreStartedAt) state.coreStartedAt = Date.now();
      state.traffic.runtimeSeconds = Math.floor((Date.now() - state.coreStartedAt) / 1000);
    } else {
      state.coreStartedAt = null;
      state.traffic.runtimeSeconds = 0;
    }
    updateStatusBar();
  }, 1000);
}

async function importProfileFromPath(path) {
  const previousActiveProfile = activeProfile().active ? activeProfile().id : null;
  try {
    const result = await invoke("import_profile_file", { path, name: null, activate: true });
    await loadProfilesSnapshot();
    try {
      const applied = await invoke("apply_active_profile");
      appendLog("info", "profile", `Dropped profile imported and applied: ${result.name} (${formatBytes(applied.bytes ?? result.bytes ?? 0)})`);
    } catch (error) {
      const rollback = await invoke("write_settings_snapshot", { settings: { ...persistedSettingsFromUi(), active_profile: previousActiveProfile } });
      applyPersistedSettings(rollback);
      await loadProfilesSnapshot();
      appendLog("error", "profile", `Dropped profile imported, but config apply failed: ${error.message ?? String(error)}`);
    }
    scheduleRender();
  } catch (error) {
    appendLog("error", "profile", `Drag-drop import failed: ${error.message ?? String(error)}`);
  }
}

bootstrap().catch((error) => {
  document.body.innerHTML = `<pre class="fatal">${escapeHtml(error.stack ?? error.message ?? String(error))}</pre>`;
});
