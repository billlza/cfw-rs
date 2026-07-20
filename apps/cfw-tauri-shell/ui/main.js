const fallbackPayload = {
  product: {
    name: "Clash for Mac",
    version: "0.1.0",
    parity_source: "Clash for Windows 0.20.39 macOS arm64 public release artifact",
  },
  pages: [
    { id: "general", title: "General", summary: "Overview, runtime status, mode, system proxy and TUN toggles." },
    { id: "proxies", title: "Proxies", summary: "Proxy groups, selections, delay indicators and quick switching." },
    { id: "profiles", title: "Profiles", summary: "Subscription import, update, validation and profile lifecycle." },
    { id: "providers", title: "Providers", summary: "Proxy providers, rule providers, health checks and update actions." },
    { id: "logs", title: "Logs", summary: "Core logs, helper logs and filtered runtime diagnostics." },
    { id: "connections", title: "Connections", summary: "Live connection list, close-all action and traffic visibility." },
    { id: "rules", title: "Rules", summary: "Rule matching visibility and router/provider diagnostics." },
    { id: "settings", title: "Settings", summary: "Shell settings, startup, deep link, helper and migration options." },
    { id: "feedback", title: "Feedback", summary: "About, feedback and migration references from the original app." },
  ],
  settings: {
    launch_at_login: false,
    random_controller_port: true,
    retain_window_bounds: true,
    show_tray_proxy_delay_indicator: true,
    check_for_updates: false,
    only_arm64_macos_supported: true,
  },
  platform: {
    minimum_macos: "13.0",
    intel_supported: false,
    system_proxy_strategy: "native SystemConfiguration manager with explicit snapshot/restore",
    helper_strategy: "SMAppService privileged helper (Login Items approval required)",
    launchd_strategy: "typed launchd contract, no ad-hoc shell scripts in product logic",
    tun_strategy: "SmAppServiceRootHelper",
  },
  quality: {
    performance: {
      multiplier_vs_cfw_02039: 3,
      cold_start_p95_ms: 700,
      page_switch_p95_ms: 16,
      proxy_toggle_p95_ms: 150,
      profile_apply_p95_ms: 450,
      max_idle_rss_mb: 90,
      log_ingest_events_per_sec: 10000,
    },
    stability: {
      crash_free_session_rate_basis_points: 9995,
      restore_system_proxy_on_exit: true,
      rollback_failed_profile_apply: true,
      idempotent_helper_install: true,
      tun_failure_restores_previous_route: true,
      single_instance_deep_link_safe: true,
    },
    parity_gates: [],
  },
};

const fallbackSettingsSnapshot = {
  persisted: false,
  paths: {
    app_home: "~/Library/Application Support/Clash for Mac",
    settings_file: "~/Library/Application Support/Clash for Mac/cfw-settings.yaml",
    config_file: "~/Library/Application Support/Clash for Mac/config.yaml",
    profiles_dir: "~/Library/Application Support/Clash for Mac/profiles",
    logs_dir: "~/Library/Application Support/Clash for Mac/logs",
    cores_dir: "~/Library/Application Support/Clash for Mac/cores",
    helpers_dir: "~/Library/Application Support/Clash for Mac/helpers",
  },
  settings: {
    schema_version: 1,
    runtime_mode: "Rule",
    active_profile: null,
    system_proxy: false,
    proxy_bypass: [],
    tun_mode: false,
    mixin: false,
    mixin_yaml: "",
    profile_parser_script: "",
    tray_script: "",
    child_process_command: "",
    allow_lan: false,
    enable_ipv6: false,
    launch_at_login: false,
    silent_start: false,
    break_connections_on_proxy_change: true,
    theme: "light",
    font_family: "",
    "interface-name": "",
    mixed_port: 7890,
    external_controller_host: "127.0.0.1",
    external_controller_port: 9090,
    secret: null,
    retain_window_bounds: true,
    show_tray_proxy_delay_indicator: true,
    randomMixedPort: false,
    delayTestUrl: "http://www.gstatic.com/generate_204",
    only_arm64_macos_supported: true,
  },
};

const fallbackCoreStatus = {
  state: "MissingBinary",
  pid: null,
  message: "Missing ~/Library/Application Support/Clash for Mac/cores/clash-darwin",
  spec: {
    binary_path: "~/Library/Application Support/Clash for Mac/cores/clash-darwin",
    config_path: "~/Library/Application Support/Clash for Mac/config.yaml",
    home_dir: "~/Library/Application Support/Clash for Mac",
    log_file: "~/Library/Application Support/Clash for Mac/logs/clash-core.log",
    controller_host: "127.0.0.1",
    controller_port: 9090,
    mixed_port: 7890,
  },
};

const state = {
  payload: fallbackPayload,
  settingsSnapshot: fallbackSettingsSnapshot,
  coreStatus: fallbackCoreStatus,
  networkDiagnostics: null,
  activePage: "general",
  mode: "Rule",
  logLevel: "info",
  proxyFilter: "",
  activeProxyGroup: null,
  collapsedProxyGroups: new Set(),
  logFilter: "all",
  logSearch: "",
  logsPaused: false,
  connectionSearch: "",
  ruleSearch: "",
  mixinYaml: "",
  profileParserScript: "",
  trayScript: "",
  childProcessCommand: "",
  connectionSort: "age",
  connectionSortDesc: false,
  connectionPaused: false,
  connectionDetailId: null,
  closingConnectionIds: new Set(),
  closingAllConnections: false,
  deepLinks: [],
  lastRefresh: "Just now",
  controllerStatus: "reference preview only",
  toggles: {
    systemProxy: false,
    tunMode: false,
    mixin: false,
    allowLan: false,
    startAtLogin: false,
    breakOnProxyChange: true,
    silentStart: false,
    hideUnavailable: true,
    enableIpv6: false,
    proxyDelayIndicator: true,
    showProxyFilter: true,
  },
  traffic: {
    upload: 0,
    download: 0,
    runtimeSeconds: 0,
    memoryMb: 0,
  },
  // Wall-clock millis when the core was last observed Running; null when stopped.
  // Drives a real uptime instead of a fabricated, always-incrementing counter.
  coreStartedAt: null,
  // Real SMAppService registration state (service_mode_status command).
  serviceModeStatus: null,
  // Live GeoIP DB status from app home (geoip.metadb / Country.mmdb).
  geoipStatus: null,
  geoipUpdating: false,
  connectionStream: {
    at: 0,
    uploadTotal: 0,
    downloadTotal: 0,
    rows: new Map(),
  },
  profiles: [],
  profileInspector: null,
  proxyGroups: [],
  logs: [],
  connections: [],
  providers: [],
  ruleProviders: [],
  rules: [],
  providerActions: new Set(),
  providerBulkActions: new Set(),
};

const navInitials = {
  general: "G",
  proxies: "P",
  profiles: "F",
  providers: "V",
  logs: "L",
  connections: "C",
  rules: "R",
  settings: "S",
  feedback: "?",
};

const primaryNavIds = new Set(["general", "proxies", "profiles", "logs", "connections", "settings", "feedback"]);
const MAX_LOG_ROWS = 200;
const MAX_CONNECTION_ROWS = 500;
let renderFrame = null;
let globalEventsBound = false;

const tauriApi = () => window.__TAURI__;
const sleep = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

const invoke = async (command, args = {}) => {
  const api = tauriApi();
  if (!api?.core?.invoke) {
    if (command === "boot_payload") return fallbackPayload;
    if (command === "quit_app") return null;
    if (command === "force_quit_app") return null;
    if (command === "current_platform_design") return fallbackPayload.platform;
    if (command === "provision_core_binary") {
      return {
        installed: false,
        source_path: null,
        target_path: fallbackCoreStatus.spec.binary_path,
        message: "Bundled core provisioning is unavailable outside Tauri",
      };
    }
    if (command === "install_core_from_url" || command === "install_latest_mihomo_core") {
      throw new Error("Core installer is unavailable outside the Tauri runtime");
    }
    if (command === "system_proxy_state") return state.toggles.systemProxy ? "Enabled" : "Disabled";
    if (command === "network_diagnostics") return null;
    if (command === "read_settings_snapshot") return fallbackSettingsSnapshot;
    if (command === "write_settings_snapshot") return { ...fallbackSettingsSnapshot, persisted: true, settings: args.settings };
    if (command === "reset_settings_snapshot") return fallbackSettingsSnapshot;
    if (command === "set_system_proxy_enabled") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, system_proxy: args.enabled } };
    }
    if (command === "set_tun_enabled") {
      if (args.enabled) throw new Error("TUN runtime is unavailable in browser preview");
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, tun_mode: args.enabled } };
    }
    if (command === "run_tray_script") return { status: 0, stdout: "preview tray script", stderr: "" };
    if (command === "run_child_process") return { status: 0, stdout: "preview child process", stderr: "" };
    if (command === "toggle_devtools") return null;
    if (command === "move_dashboard_to_nearest_monitor") return null;
    if (command === "set_mixin_enabled") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, mixin: args.enabled } };
    }
    if (command === "set_launch_at_login_enabled") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, launch_at_login: args.enabled } };
    }
    if (command === "install_helper_service") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, service_mode: "installed" } };
    }
    if (command === "uninstall_helper_service") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, service_mode: "not-installed" } };
    }
    if (command === "controller_snapshot") return null;
    if (command === "providers_snapshot") return null;
    if (command === "rules_snapshot") return null;
    if (command === "update_proxy_provider") return null;
    if (command === "update_rule_provider") return null;
    if (command === "health_check_proxy_provider") return null;
    if (command === "update_all_proxy_providers") return emptyProviderBatch("update-proxy");
    if (command === "update_all_rule_providers") return emptyProviderBatch("update-rule");
    if (command === "health_check_all_proxy_providers") return emptyProviderBatch("health-check-proxy");
    if (command === "service_mode_status") return "Unknown";
    if (command === "enable_service_mode") return "RequiresApproval";
    if (command === "disable_service_mode") return null;
    if (command === "geoip_database_status") {
      return {
        present: false,
        file_name: "geoip.metadb",
        path: `${fallbackSettingsSnapshot.paths.app_home}/geoip.metadb`,
        mtime_ms: null,
        size_bytes: null,
      };
    }
    if (command === "update_geoip_database") {
      const now = Date.now();
      return {
        status: {
          present: true,
          file_name: "geoip.metadb",
          path: `${fallbackSettingsSnapshot.paths.app_home}/geoip.metadb`,
          mtime_ms: now,
          size_bytes: 1024,
        },
        source_url: "https://example.invalid/geoip.metadb",
        bytes: 1024,
      };
    }
    if (command === "refresh_tray_menu") return null;
    if (command === "start_connections_stream") return null;
    if (command === "start_log_stream") return null;
    if (command === "parse_deep_links") {
      return (args.urls ?? []).map((url) => ({ raw: url, intent: null, error: "parse_deep_links is unavailable outside Tauri" }));
    }
    if (command === "import_profile_url") {
      const id = `import-${Date.now()}`;
      return { id, name: args.name ?? "Imported Profile", path: `${fallbackSettingsSnapshot.paths.profiles_dir}/${id}.yaml`, bytes: 0, activated: args.activate };
    }
    if (command === "import_profile_text") {
      const id = `local-${Date.now()}`;
      return { id, name: args.name ?? "Local Profile", path: `${fallbackSettingsSnapshot.paths.profiles_dir}/${id}.yaml`, bytes: args.body?.length ?? 0, activated: args.activate };
    }
    if (command === "update_profile") throw new Error("Profile update is unavailable outside the Tauri runtime");
    if (command === "read_profile_text") {
      return {
        id: args.id,
        name: args.id,
        path: `${fallbackSettingsSnapshot.paths.profiles_dir}/${args.id}.yaml`,
        body: "proxies: []\nproxy-groups: []\nrules: []\n",
        generated_body: "mixed-port: 7890\nproxies: []\nproxy-groups: []\nrules: []\n",
        active: false,
        source_url: null,
      };
    }
    if (command === "save_profile_text") return { id: args.id, path: "", bytes: args.body?.length ?? 0, active: false };
    if (command === "profile_qrcode_svg") throw new Error("Profile QRCode is unavailable outside the Tauri runtime");
    if (command === "profiles_snapshot") return [];
    if (command === "delete_profile") return true;
    if (command === "reveal_profile") return null;
    if (command === "reveal_home_directory") return null;
    if (command === "reveal_logs_directory") return null;
    if (command === "apply_active_profile") throw new Error("Profile apply is unavailable outside the Tauri runtime");
    if (command === "set_proxy_mode") return null;
    if (command === "set_allow_lan") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, allow_lan: args.enabled } };
    }
    if (command === "set_ipv6") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, enable_ipv6: args.enabled } };
    }
    if (command === "set_log_level") return null;
    if (command === "select_proxy") return null;
    if (command === "test_proxy_delays") return [];
    if (command === "close_connection") return null;
    if (command === "close_all_connections") return null;
    if (command === "flush_fake_ip_cache") return null;
    if (command === "core_status") return fallbackCoreStatus;
    if (command === "start_core") return fallbackCoreStatus;
    if (command === "stop_core") return { ...fallbackCoreStatus, state: "Stopped", message: "Core stopped" };
    return null;
  }
  return api.core.invoke(command, args);
};

const listen = async (event, handler) => {
  const api = tauriApi();
  if (!api?.event?.listen) return () => {};
  return api.event.listen(event, handler);
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatRuntime(seconds) {
  const hours = Math.floor(seconds / 3600).toString().padStart(2, "0");
  const minutes = Math.floor((seconds % 3600) / 60).toString().padStart(2, "0");
  const secs = Math.floor(seconds % 60).toString().padStart(2, "0");
  return `${hours} : ${minutes} : ${secs}`;
}

// Map the real SMAppService status (service_mode_status command) to a label.
function serviceModeLabel(status) {
  switch (status) {
    case "Enabled":
      return "Enabled";
    case "RequiresApproval":
      return "Needs Approval";
    case "NotRegistered":
    case "NotFound":
      return "Not Installed";
    default:
      return "Unknown";
  }
}

function serviceModeNeedsAttention(status) {
  return status !== "Enabled";
}

function formatGeoipLabel(status, updating) {
  if (updating) return "Updating…";
  if (!status) return "Loading…";
  if (!status.present) return "Missing";
  if (status.mtime_ms == null) return status.file_name || "Present";
  const date = new Date(status.mtime_ms);
  if (Number.isNaN(date.getTime())) return status.file_name || "Present";
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function formatRate(mbPerSecond) {
  const kb = mbPerSecond * 1024;
  if (kb < 1024) return `${kb.toFixed(kb < 10 ? 2 : 0)} KB/s`;
  return `${mbPerSecond.toFixed(1)} MB/s`;
}

function emptyProviderBatch(action) {
  return { action, requested: 0, succeeded: [], failed: [] };
}

function providerActionKey(scope, name) {
  return `${scope}:${name}`;
}

function providerBatchSummary(label, result) {
  const requested = Number(result?.requested ?? 0);
  const succeeded = result?.succeeded?.length ?? 0;
  const failed = result?.failed?.length ?? 0;
  const failures = (result?.failed ?? []).slice(0, 3).map((item) => `${item.name}: ${item.error}`).join("; ");
  return `${label}: ${succeeded}/${requested} succeeded${failed ? `, ${failed} failed${failures ? ` (${failures})` : ""}` : ""}`;
}

function providerBatchSucceeded(result) {
  return (result?.failed?.length ?? 0) === 0;
}

function latestDelay(history = []) {
  const last = history.at(-1);
  return Number.isFinite(last?.delay) ? last.delay : null;
}

function normalizeLevel(level) {
  const value = String(level ?? "info").toLowerCase();
  if (["warn", "wrn", "warning"].includes(value)) return "warning";
  if (["err", "error", "fatal", "ftl"].includes(value)) return "error";
  if (["debug", "dbg", "trace", "trc"].includes(value)) return "debug";
  return "info";
}

function safeRegex(value) {
  if (!value) return null;
  try {
    return new RegExp(value, "i");
  } catch (_error) {
    return null;
  }
}

function pageById(id) {
  return state.payload.pages.find((page) => page.id === id) ?? state.payload.pages[0];
}

function activeProfile() {
  return state.profiles.find((profile) => profile.active)
    ?? state.profiles[0]
    ?? { id: "none", name: "No Profile", type: "Local", updated: "never", rules: 0, traffic: "0 B", active: false };
}

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
    theme: document.querySelector("[data-theme-setting]")?.value ?? current.theme ?? "light",
    font_family: document.querySelector("[data-font-family]")?.value?.trim() ?? current.font_family ?? "",
    "interface-name": document.querySelector("[data-outbound-interface]")?.value?.trim() ?? current["interface-name"] ?? current.interfaceName ?? "",
    randomMixedPort: document.querySelector("[data-random-mixed-port]")?.checked
      ?? Boolean(current.randomMixedPort ?? current.random_mixed_port),
    delayTestUrl: document.querySelector("[data-delay-test-url]")?.value?.trim()
      || current.delayTestUrl
      || current.delay_test_url
      || "http://www.gstatic.com/generate_204",
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
  if (groups.length) {
    state.proxyGroups = groups.map((group) => ({
      name: group.name,
      type: group.kind,
      now: group.now ?? group.options?.[0] ?? "DIRECT",
      options: (group.options ?? []).map((name) => {
        const node = proxyNodes.get(name);
        return {
          name,
          delay: latestDelay(node?.history ?? group.history),
          dead: false,
          kind: node?.kind ?? node?.type ?? group.kind ?? "Proxy",
          udp: node?.udp ?? null,
        };
      }),
    }));
  }

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

function renderGeneral() {
  const profile = activeProfile();
  const persisted = state.settingsSnapshot?.settings ?? fallbackSettingsSnapshot.settings;
  const product = state.payload.product ?? fallbackPayload.product;
  const appVersion = product.version ?? "0.1.0";
  const core = state.coreStatus ?? fallbackCoreStatus;
  const coreRunning = core.state === "Running";
  const controller = `${persisted.external_controller_host}:${persisted.external_controller_port}`;
  const statusDot = coreRunning ? "cfw-status-dot on" : "cfw-status-dot";
  const logLevel = state.logLevel ?? persisted.logLevel ?? persisted["log-level"] ?? "info";
  const serviceMode = serviceModeLabel(state.serviceModeStatus);
  const randomPort = Boolean(persisted.randomMixedPort ?? persisted.random_mixed_port);
  return `
    <div class="cfw-general-view">
      <section class="cfw-header">
        <div class="cfw-app-mark">${renderCatLogo()}</div>
        <div class="cfw-title">
          <span>Clash for Mac</span>
          <small>v${escapeHtml(appVersion)}</small>
        </div>
      </section>

      <section class="cfw-content">
        <div class="cfw-row">
          <div class="cfw-row-left">Port</div>
          <div class="cfw-row-right">
            <label class="proxy-tool check" title="Pick a free loopback port when the core starts">
              <input type="checkbox" data-random-mixed-port ${randomPort ? "checked" : ""} />
              <span>random ${randomPort ? "on" : "off"}</span>
            </label>
            <input class="cfw-number" data-mixed-port type="number" min="1" max="65535" value="${persisted.mixed_port}" aria-label="mixed-port" ${randomPort ? "disabled" : ""}>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Allow LAN</div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">Bind: ${state.toggles.allowLan ? "*" : "127.0.0.1"}</span>
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
          <div class="cfw-row-right">
            ${renderInlineSwitch("enableIpv6", "IPv6")}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Clash Core <button class="inline-icon" data-action="open-settings" title="Core settings">⚙</button><button class="inline-icon" data-action="open-settings" title="Core list">▤</button></div>
          <div class="cfw-row-right core-action-zone" data-action="${core.state === "MissingBinary" ? "install-latest-core" : coreRunning ? "stop-core" : "start-core"}" title="${coreRunning ? "Stop core" : "Start core"}">
            <i class="${statusDot}"></i>
            <span class="cfw-link-value core-state-button">${coreRunning ? "Connected" : escapeHtml(core.state)}</span>
            ${core.state === "MissingBinary" ? '<span class="cfw-text-button">Install</span>' : ""}
            <span class="inline-icon play">${coreRunning ? "■" : "▶"}</span>
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
            <button class="cfw-text-button" data-action="update-geoip-database" title="${state.geoipStatus?.path ? escapeHtml(state.geoipStatus.path) : "Download / refresh GeoIP database"}">${escapeHtml(formatGeoipLabel(state.geoipStatus, state.geoipUpdating))}</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Service Mode${serviceModeNeedsAttention(state.serviceModeStatus) ? ' <span class="tiny-warn">!</span>' : ""}</div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${serviceMode}</span>
            <button class="cfw-text-button" data-action="manage-service-mode">Manage</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">TUN Mode <span class="tiny-info">i</span><button class="inline-icon" data-action="open-settings">⚙</button><button class="inline-icon" data-action="open-settings">↻</button></div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${state.toggles.tunMode ? serviceMode : "Service Mode required"}</span>
            ${renderInlineSwitch("tunMode", "TUN Mode")}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Mixin <span class="tiny-info">i</span><button class="inline-icon" data-action="open-settings">⚙</button></div>
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
  if (delay < 0) return "dead";
  if (delay === 0) return "direct";
  if (delay < 80) return "fast";
  if (delay < 180) return "mid";
  return "slow";
}

function delayLabel(delay) {
  if (delay === null || delay === undefined) return "Pending";
  if (delay < 0) return "N/A";
  if (delay === 0) return "DIRECT";
  return `${delay} ms`;
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

/** CFW Proxies toolbar glyphs (filled, ~18px). */
function proxyToolIcon(kind) {
  const common = 'width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"';
  switch (kind) {
    case "filter":
      // Globe + magnifying glass (Show Filter)
      return `<svg ${common} fill="currentColor"><path d="M12 2a10 10 0 1 0 9.95 11H14a2 2 0 0 1-2-2V2.05A10 10 0 0 0 12 2zm1 0v8h8A9 9 0 0 0 13 2z"/><path d="M16.5 15.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7zm0 1.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4z"/><path d="M19.2 19.2 22 22" stroke="currentColor" stroke-width="2" stroke-linecap="round" fill="none"/></svg>`;
    case "break":
      // Octagon + exclamation (Break / close connections)
      return `<svg ${common} fill="currentColor"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86L7.86 2zm1.03 2L4 8.89v6.22L8.89 20h6.22L20 15.11V8.89L15.11 4H8.89z"/><rect x="11" y="7" width="2" height="7" rx="1"/><circle cx="12" cy="17" r="1.2"/></svg>`;
    case "delay":
      // Wi‑Fi bars with slash (Latency test)
      return `<svg ${common} fill="currentColor"><path d="M12 18.5a1.75 1.75 0 1 0 0 3.5 1.75 1.75 0 0 0 0-3.5zm-4.24-3.05a6 6 0 0 1 8.48 0l-1.42 1.41a4 4 0 0 0-5.64 0l-1.42-1.41zm-2.83-2.83a10 10 0 0 1 14.14 0l-1.41 1.41a8 8 0 0 0-11.32 0L4.93 12.62z"/><path d="M4 4l16 16" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>`;
    case "eye":
      // Eye (Hide unavailable)
      return `<svg ${common} fill="currentColor"><path d="M12 5c-5 0-9.27 3.11-11 7 1.73 3.89 6 7 11 7s9.27-3.11 11-7c-1.73-3.89-6-7-11-7zm0 12a5 5 0 1 1 0-10 5 5 0 0 1 0 10zm0-2.5A2.5 2.5 0 1 0 12 9a2.5 2.5 0 0 0 0 5z"/></svg>`;
    case "eye-off":
      return `<svg ${common} fill="currentColor"><path d="M2.1 3.51 3.5 2.1l18.4 18.4-1.41 1.41-3.1-3.1A12.4 12.4 0 0 1 12 19c-5 0-9.27-3.11-11-7a13.3 13.3 0 0 1 4.2-4.86L2.1 3.51zM12 7c5 0 9.27 3.11 11 7a13.2 13.2 0 0 1-3.36 4.22l-2.2-2.2A5 5 0 0 0 9 8.56L7.2 6.75C8.66 7.1 10.26 7 12 7zm-2.12 2.12A2.5 2.5 0 0 1 14.9 14.1l-4.99-4.98z"/></svg>`;
    default:
      return "";
  }
}

function renderProxies() {
  const filter = state.proxyFilter.trim().toLowerCase();
  const groups = state.proxyGroups
    .map((group) => ({
      ...group,
      options: group.options.filter((node) => {
        const matchesFilter = !filter || group.name.toLowerCase().includes(filter) || node.name.toLowerCase().includes(filter);
        const shouldHide = state.toggles.hideUnavailable && node.dead && group.now !== node.name;
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
  const hideUnavailable = Boolean(state.toggles.hideUnavailable);
  const showFilter = state.toggles.showProxyFilter !== false;
  return `
    <div class="proxy-layout">
      <div class="mode-switch proxy-mode-header" role="group" aria-label="Proxy mode">
        ${["Global", "Rule", "Direct", "Script"].map((mode) => `
          <button class="${state.mode === mode ? "selected" : ""}" data-mode="${mode}">${mode} <span>${modeIcon(mode)}</span></button>
        `).join("")}
      </div>

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
              ${showFilter ? `<input class="proxy-filter" data-proxy-filter placeholder="Filter" value="${escapeHtml(state.proxyFilter)}" aria-label="Filter proxies" />` : ""}
              <button class="proxy-tool ${showFilter ? "active" : ""}" data-action="toggle-proxy-filter" title="Show Filter">${proxyToolIcon("filter")}</button>
              <button class="proxy-tool" data-action="break-proxy-connections" title="Break Connections">${proxyToolIcon("break")}</button>
              <button class="proxy-tool" data-action="delay-test" title="Latency Test">${proxyToolIcon("delay")}</button>
              <button class="proxy-tool ${hideUnavailable ? "active" : ""}" data-action="toggle-hide-unavailable" title="Hide Unavailable">${proxyToolIcon(hideUnavailable ? "eye-off" : "eye")}</button>
            </div>
          </div>
          <div class="cfw-proxy-content">
            <div class="cfw-node-grid">
              ${activeGroup.options.map((node) => `
                <button class="cfw-node-card ${activeGroup.now === node.name ? "selected" : ""} ${manual ? "" : "readonly"}" ${manual ? `data-group="${escapeHtml(activeGroup.name)}" data-node="${escapeHtml(node.name)}"` : "disabled"} title="${manual ? "Select proxy" : "This Clash group type is controlled by the core"}">
                  <i></i>
                  <span>
                    <strong>${nodePrefix(node.name)}${escapeHtml(node.name)}</strong>
                    <small>${escapeHtml(node.kind ?? "Proxy")} ${node.udp === false ? "" : "<em>UDP</em>"}</small>
                  </span>
                  <b class="${delayClass(node.delay)}">${delayLabel(node.delay)}</b>
                </button>
              `).join("")}
            </div>
            <aside class="cfw-group-rail">
              ${groups.map((group) => `
                <button class="${group.name === activeGroup.name ? "active" : ""}" data-proxy-group-tab="${escapeHtml(group.name)}" title="${escapeHtml(group.name)}">${escapeHtml(groupRailLabel(group.name))}</button>
              `).join("")}
            </aside>
          </div>
        ` : '<p class="empty">Controller unavailable. No live proxy groups are being displayed.</p>'}
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
  if (profile.subscriptionUserinfo) {
    const parsed = parseSubscriptionUserinfo(profile.subscriptionUserinfo);
    if (parsed?.expireLabel) return parsed.expireLabel;
    return "remote";
  }
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
  let expireLabel = null;
  if (Number.isFinite(expire) && expire > 0) {
    const date = new Date(expire * 1000);
    if (!Number.isNaN(date.getTime())) {
      const pad = (n) => String(n).padStart(2, "0");
      expireLabel = `exp ${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
    }
  }
  return { used, total: Number.isFinite(total) ? total : null, percent, expireLabel };
}

function profileProgressWidth(profile) {
  const parsed = parseSubscriptionUserinfo(profile.subscriptionUserinfo);
  if (parsed?.percent != null) return parsed.percent;
  // No usage quota from the subscription — keep the bar empty (never invent %).
  return 0;
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
                <span>${escapeHtml(profile.traffic)}</span>
                <span>${profile.rules.toLocaleString()} rules</span>
                <span>${escapeHtml(subscriptionLabel(profile))}</span>
              </div>
              <div class="profile-progress" title="${profile.subscriptionUserinfo ? escapeHtml(profile.subscriptionUserinfo) : "No subscription usage quota"}"><b style="width:${profileProgressWidth(profile).toFixed(1)}%"></b></div>
            </div>
            <div class="profile-card-primary">
              ${profile.sourceUrl
                ? `<button data-update-profile="${escapeHtml(profile.id)}" title="Update subscription">⟳</button>`
                : `<button data-profile-action="edit" data-profile-id="${escapeHtml(profile.id)}" title="Edit local profile">‹›</button>`}
            </div>
            <div class="profile-card-secondary">
              ${profile.active ? "" : `<button data-profile="${escapeHtml(profile.id)}" title="Select profile">✓</button>`}
              <button data-profile-action="diff" data-profile-id="${escapeHtml(profile.id)}" title="Diff">≋</button>
              <button data-profile-action="qrcode" data-profile-id="${escapeHtml(profile.id)}" ${profile.sourceUrl ? "" : "disabled"} title="QRCode">▦</button>
              <button data-reveal-profile="${escapeHtml(profile.id)}" title="Show in Finder">⌕</button>
              <button data-delete-profile="${escapeHtml(profile.id)}" title="Delete">×</button>
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

function renderConnections() {
  const connections = visibleConnections();
  const detail = state.connections.find((connection) => connection.id === state.connectionDetailId);
  const totalUp = formatBytes(state.connectionStream.uploadTotal);
  const totalDown = formatBytes(state.connectionStream.downloadTotal);
  return `
    <div class="connections-layout">
      <section class="cfw-conn-header">
        <h1>Connections</h1>
        <div class="cfw-conn-search">
          <span>●</span>
          <input value="${escapeHtml(state.connectionSearch)}" data-connection-search aria-label="Search connections" placeholder="Search connections" />
          ${state.connectionSearch ? '<button data-action="clear-connection-search">×</button>' : ""}
        </div>
        <strong>Total: ↑ ${totalUp} ↓ ${totalDown}</strong>
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
        <button class="danger" data-action="close-all" ${state.closingAllConnections ? "disabled" : ""}>${state.closingAllConnections ? "Closing..." : `Close All (${connections.length})`}</button>
      </section>

      <section class="cfw-conn-scroll">
        ${connections.map((connection) => `
          <article class="cfw-conn-item">
            <div class="conn-main">
              <h3>${escapeHtml(connection.host)}</h3>
              <div class="conn-chips">
                <span class="conn1">${escapeHtml(connection.rule || "MATCH")}</span>
                ${(connection.chains ?? []).slice(0, 4).map((chain, index) => `<span class="conn${(index % 6) + 2}">${escapeHtml(chain)}</span>`).join("")}
                <span class="conn7">${escapeHtml(connection.metadata?.network ?? connection.metadata?.type ?? "tcp")}</span>
              </div>
            </div>
            <div class="conn-traffic">
              <b>↑ ${escapeHtml(connection.upload)}</b>
              <b>↓ ${escapeHtml(connection.download)}</b>
              <small>${escapeHtml(connection.speed ?? "0 B/s")}</small>
            </div>
            <div class="conn-actions">
              <button data-connection-detail="${escapeHtml(connection.id)}">Info</button>
              <button data-close-connection="${escapeHtml(connection.id)}" ${state.closingConnectionIds.has(connection.id) ? "disabled" : ""}>${state.closingConnectionIds.has(connection.id) ? "Closing" : "Close"}</button>
            </div>
          </article>
        `).join("")}
      </section>
      ${detail ? renderConnectionDetail(detail) : ""}
    </div>
  `;
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
  return `
    <div class="feedback-layout">
      <section class="panel hero-panel">
        <div>
          <p class="label">Feedback</p>
          <h3>${escapeHtml(product.name)} v${escapeHtml(product.version ?? "0.1.0")}</h3>
          <p class="muted">Parity target is CFW 0.20.39; this build is the Apple Silicon beta (${escapeHtml(product.version ?? "0.1.0")}).</p>
        </div>
        <span class="badge">ARM64 macOS only</span>
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
      renderToggle("proxyDelayIndicator", "Tray delay indicator", "Show selected-node latency in the menu-bar tooltip."),
      (() => {
        const bypass = (persisted.proxy_bypass ?? []).join("\n");
        return `
          <label class="setting-row setting-control-row">
            <span>
              <b>Bypass Domains</b>
              <small>One host or CIDR per line. Empty uses the built-in LAN/localhost defaults. Applied when System Proxy turns on.</small>
            </span>
            <textarea class="mixin-editor" data-proxy-bypass spellcheck="false" rows="5">${escapeHtml(bypass)}</textarea>
          </label>`;
      })(),
      renderSettingValue("PAC Script", "Not in 0.1.0 beta", "CFW PAC editor is deferred; System Proxy uses HTTP/HTTPS/SOCKS + bypass list."),
    ]],
    ["Mixin", [renderToggle("mixin", "Mixin", "Merge YAML/JS mixin before profile apply."), renderSettingValue("Mixin YAML", "Editor active", "The YAML merge editor below is persisted and applied before config reload.")]],
    ["Proxies", [
      renderToggle("hideUnavailable", "Hide unavailable proxies", "Keep proxy group list compact."),
      renderSettingInput(
        "Delay test URL",
        persisted.delayTestUrl ?? persisted.delay_test_url ?? "http://www.gstatic.com/generate_204",
        "http://www.gstatic.com/generate_204",
        "Used by Proxies → Delay Test against the live controller.",
        "data-delay-test-url"
      ),
    ]],
    ["Connections", [renderToggle("breakOnProxyChange", "Break connections", "Disconnect sockets after proxy or profile changes."), renderSettingValue("Show Process", "Not in 0.1.0 beta", "CFW process-path column is deferred on this macOS beta.")]],
    ["Providers", [renderSettingValue("Use CFW Editor", "Profile editor active", "Profile YAML edit/diff is built in; provider file editor remains behind controller metadata."), renderSettingValue("Update All", "Controller-backed", "Proxy and rule providers expose bulk update actions.")]],
    ["Outbound", [renderSettingInput("Interface Name", outboundInterface, recommendedInterface, "Bind Clash outbound sockets to a macOS BSD interface; blank keeps Clash automatic.", "data-outbound-interface")]],
    ["Child Processes", [renderSettingValue("Processes", "Action runner", "Spawn child processes through a typed Rust command boundary.")]],
    ["Profiles", [renderSettingValue("Parsers", "Safe script active", "Apply parser scripts before mixin/runtime config generation."), renderSettingValue("Headers", "Captured", "Remote imports persist subscription-userinfo and profile-update-interval metadata.")]],
    ["Logs", [renderSettingValue("Request Logs", "Preload + stream", "Original supports log preload, filters and log-level changes.")]],
    ["SSID", [renderSettingValue("SSID Policy", "Not in 0.1.0 beta", "CFW could vary proxy/profile by Wi-Fi SSID. Deferred — this toggle is intentionally unavailable.")]],
    ["Actions", [renderSettingValue("Tray Script", "Rust action runner", "Run Tray Script action is executable from settings and tray.")]],
    ["Shortcuts", [renderSettingValue("Mode shortcuts", "Active", "Cmd+1..6, Cmd+G/R/D/S/P/T/M mirror original dashboard shortcuts.")]],
    ["CFW Editor", [renderSettingValue("Diff Editor", "Not in 0.1.0 beta", "Built-in YAML edit exists on Profiles; Monaco-style side-by-side diff is deferred.")]],
    ["Cache", [renderSettingAction("Fake IP Cache", "Controller-backed", "Flush Mihomo fake-ip cache through /cache/fakeip/flush.", "flush-fake-ip-cache", "Flush")]],
    ["Experimental Features", [renderSettingValue("DHCP Server", "Not in 0.1.0 beta", "CFW macOS DHCP server switch is not shipped in this beta."), renderToggle("enableIpv6", "IPv6", "Expose IPv6 option in generated Clash config.")]],
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
        renderToggle("startAtLogin", "Start at Login", "Launch Clash for Mac after login."),
        renderToggle("silentStart", "Silent Start", "Start hidden in tray without opening dashboard."),
        renderToggle("proxyDelayIndicator", "Tray delay indicator", "Show current proxy latency in tray quick menu."),
      ])}
      ${renderSettingsGroup("Core", [
        renderSettingValue("mixed-port", String(persisted.mixed_port), "HTTP, HTTPS and SOCKS entry point."),
        renderSettingValue("external-controller", controller, "Local Clash controller endpoint."),
        renderSettingValue("secret", persisted.secret ? "••••••••" : "empty", "Controller secret stored in cfw-settings.yaml."),
        renderToggle("enableIpv6", "IPv6", "Expose IPv6 option in generated Clash config."),
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
        renderToggle("hideUnavailable", "Hide unavailable proxies", "Keep proxy pages readable when providers degrade."),
        renderSettingValue("TUN", platform.tun_strategy ?? "SmAppServiceRootHelper", "Root mihomo via SMAppService helper — not NetworkExtension."),
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
  if (renderFrame !== null) return;
  renderFrame = window.requestAnimationFrame(() => {
    renderFrame = null;
    renderPage();
  });
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
      state.activePage = page;
      await invoke("open_page", { page });
      renderPage();
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
      const id = event.currentTarget.dataset.profile;
      const previousActiveProfile = activeProfile().active ? activeProfile().id : null;
      const snapshot = await invoke("write_settings_snapshot", { settings: { ...persistedSettingsFromUi(), active_profile: id } });
      applyPersistedSettings(snapshot);
      await loadProfilesSnapshot();
      try {
        const applied = await invoke("apply_active_profile");
        appendLog("info", "profile", `Profile switched to ${activeProfile().name}; config.yaml updated (${formatBytes(applied.bytes ?? 0)})`);
      } catch (error) {
        const rollback = await invoke("write_settings_snapshot", { settings: { ...persistedSettingsFromUi(), active_profile: previousActiveProfile } });
        applyPersistedSettings(rollback);
        await loadProfilesSnapshot();
        appendLog("error", "profile", `Profile switched, but config apply failed: ${error.message ?? String(error)}`);
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
      const profile = state.profiles.find((item) => item.id === id);
      if (!window.confirm(`Delete profile "${profile?.name ?? id}"? This removes the managed YAML file.`)) return;
      try {
        const deleted = await invoke("delete_profile", { id });
        await loadProfilesSnapshot();
        appendLog(deleted ? "warning" : "info", "profile", deleted ? `Profile deleted: ${id}` : `Profile already missing: ${id}`);
      } catch (error) {
        appendLog("error", "profile", `Delete failed: ${error.message ?? String(error)}`);
      }
      renderPage();
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
  if (globalEventsBound) return;
  globalEventsBound = true;

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
      await loadNetworkDiagnostics();
    } else if (key === "tunMode") {
      const snapshot = await invoke("set_tun_enabled", { enabled: checked });
      applyPersistedSettings(snapshot);
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
    }
    appendLog("info", source, `${key} changed to ${checked ? "on" : "off"}`);
  } catch (error) {
    state.toggles[key] = previous;
    throw error;
  }
}

async function handleAction(action) {
  if (action === "open-settings") {
    state.activePage = "settings";
  }
  if (action === "toggle-proxy-filter") {
    state.toggles.showProxyFilter = !state.toggles.showProxyFilter;
    if (!state.toggles.showProxyFilter) state.proxyFilter = "";
  }
  if (action === "toggle-hide-unavailable") {
    state.toggles.hideUnavailable = !state.toggles.hideUnavailable;
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
    if (tauriApi()?.core?.invoke) {
      const names = [...new Set(state.proxyGroups.flatMap((group) => group.options.map((node) => node.name)))]
        .filter((name) => !["DIRECT", "REJECT"].includes(name.toUpperCase()));
      if (!names.length) {
        appendLog("warning", "proxy", "No proxy nodes available for delay test");
      } else {
        const delayUrl = state.settingsSnapshot?.settings?.delayTestUrl
          ?? state.settingsSnapshot?.settings?.delay_test_url
          ?? null;
        const results = await invoke("test_proxy_delays", { proxies: names, url: delayUrl, timeoutMs: 5000 });
        const delayByName = new Map((results ?? []).filter((item) => Number.isFinite(item.delay)).map((item) => [item.name, item.delay]));
        const errorByName = new Map((results ?? []).filter((item) => item.error).map((item) => [item.name, item.error]));
        state.proxyGroups.forEach((group) => {
          group.options.forEach((node) => {
            if (delayByName.has(node.name)) {
              node.delay = delayByName.get(node.name);
              node.dead = false;
            } else if (errorByName.has(node.name)) {
              node.delay = -1;
              node.dead = true;
            }
          });
        });
        const failed = (results ?? []).filter((item) => item.error).length;
        appendLog(failed ? "warning" : "info", "proxy", `Delay Test completed: ${delayByName.size} updated${failed ? `, ${failed} failed` : ""}`);
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
      appendLog("info", "core", state.coreStatus.message);
      await loadControllerSnapshot();
    } catch (error) {
      state.coreStatus = await invoke("core_status");
      appendLog("error", "core", error.message ?? String(error));
    }
  }
  if (action === "install-latest-core") {
    try {
      appendLog("info", "core", "Checking pinned darwin-arm64 Mihomo core package...");
      const result = await invoke("install_latest_mihomo_core");
      state.coreStatus = await invoke("core_status");
      appendLog("info", "core", `Core installed: ${formatBytes(result.bytes ?? 0)} · ${String(result.sha256 ?? "").slice(0, 12)}`);
    } catch (error) {
      appendLog("error", "core", `Core install failed: ${error.message ?? String(error)}`);
    }
  }
  if (action === "stop-core") {
    try {
      state.coreStatus = await invoke("stop_core");
      appendLog("warning", "core", state.coreStatus.message);
    } catch (error) {
      appendLog("error", "core", error.message ?? String(error));
    }
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
    if (activeProfile().active) {
      const applied = await invoke("apply_active_profile");
      appendLog("info", "settings", `cfw-settings.yaml saved; active config reapplied (${formatBytes(applied.bytes ?? 0)})`);
    } else {
      appendLog("info", "settings", "cfw-settings.yaml saved");
    }
  }
  if (action === "reload-settings") {
    await loadSettingsSnapshot();
    appendLog("info", "settings", "cfw-settings.yaml reloaded");
  }
  if (action === "manage-service-mode") {
    try {
      const status = await invoke("enable_service_mode");
      state.serviceModeStatus = status;
      if (status === "RequiresApproval") {
        appendLog(
          "warning",
          "service",
          'Service Mode needs approval: System Settings → General → Login Items & Extensions → enable "Clash for Mac"'
        );
      } else if (status === "Enabled") {
        appendLog("info", "service", "Service Mode enabled");
      } else {
        appendLog("warning", "service", `Service Mode status: ${serviceModeLabel(status)}`);
      }
    } catch (error) {
      appendLog("warning", "service", `Service Mode enable failed: ${error.message ?? String(error)}`);
    }
    await loadCoreStatus();
  }
  if (action === "update-geoip-database") {
    if (state.geoipUpdating) return;
    const custom = window.prompt(
      "GeoIP database URL (leave blank for MetaCubeX geoip.metadb):",
      ""
    );
    if (custom === null) return;
    state.geoipUpdating = true;
    renderPage();
    try {
      const result = await invoke("update_geoip_database", {
        url: custom.trim() ? custom.trim() : null,
      });
      state.geoipStatus = result.status;
      appendLog(
        "info",
        "geoip",
        `Updated ${result.status.file_name} (${formatBytes(result.bytes)}) from ${result.source_url}`
      );
    } catch (error) {
      appendLog("warning", "geoip", `GeoIP update failed: ${error.message ?? String(error)}`);
    } finally {
      state.geoipUpdating = false;
    }
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
    if (!window.confirm("Reset all Clash for Mac settings to defaults? Imported profile files are kept, but the active profile pointer and runtime toggles reset.")) {
      return;
    }
    const snapshot = await invoke("reset_settings_snapshot");
    applyPersistedSettings(snapshot);
    await loadProfilesSnapshot();
    appendLog("warning", "settings", "cfw-settings.yaml reset to defaults");
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

async function openProfileInspector(id, mode) {
  const profile = await invoke("read_profile_text", { id });
  const inspector = { id, mode, profile };
  if (mode === "qrcode") {
    try {
      inspector.svg = await invoke("profile_qrcode_svg", { id });
    } catch (error) {
      inspector.error = error.message ?? String(error);
    }
  }
  state.profileInspector = inspector;
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

async function loadNetworkDiagnostics() {
  try {
    state.networkDiagnostics = await invoke("network_diagnostics");
  } catch (error) {
    state.networkDiagnostics = null;
    appendLog("warning", "network", `Unable to inspect macOS network services: ${error.message ?? String(error)}`);
  }
}

async function loadCoreStatus() {
  try {
    state.coreStatus = await invoke("core_status");
  } catch (error) {
    state.coreStatus = fallbackCoreStatus;
    appendLog("warning", "core", error.message ?? String(error));
  }
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
    if (tauriApi()?.core?.invoke) {
      state.profiles = profiles.map((profile) => ({
        id: profile.id,
        name: profile.name,
        type: profile.source_url ? "Remote" : "Local",
        updated: profile.updated_epoch_secs ? new Date(profile.updated_epoch_secs * 1000).toLocaleString() : "unknown",
        rules: profile.rule_count ?? 0,
        traffic: formatBytes(profile.bytes ?? 0),
        active: Boolean(profile.active),
        path: profile.path,
        sourceUrl: profile.source_url ?? null,
        subscriptionUserinfo: profile.subscription_userinfo ?? null,
        updateInterval: profile.update_interval ?? null,
      }));
    }
    return true;
  } catch (error) {
    if (tauriApi()?.core?.invoke) state.profiles = [];
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
  await loadNetworkDiagnostics();
  await loadCoreStatus();
  await loadProfilesSnapshot();
  renderPage();
  Promise.all([loadControllerSnapshotWithRetry(), loadProvidersSnapshot()]).finally(renderPage);

  document.getElementById("reload-button").addEventListener("click", reloadPayload);

  await listen("cfw://page", (event) => {
    state.activePage = event.payload;
    renderPage();
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

  await listen("cfw://connections-snapshot", (event) => {
    if (state.connectionPaused) return;
    applyConnectionsSnapshot(event.payload);
    updateStatusBar();
    if (state.activePage === "connections" || state.activePage === "general") scheduleRender();
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
  }, 2000);
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
