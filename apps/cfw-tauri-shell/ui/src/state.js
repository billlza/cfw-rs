// Dashboard pages. 0.3.5 received this list from `boot_payload`; the 0.4.0
// payload carries product identity only, so the page list lives here instead of
// being invented from a stale backend field.
export const PAGES = [
  { id: "general", title: "General", summary: "Overview, runtime status, mode, system proxy and TUN switches." },
  { id: "proxies", title: "Proxies", summary: "Proxy groups, selections, delay indicators and quick switching." },
  { id: "profiles", title: "Profiles", summary: "Subscription import, update, validation and profile lifecycle." },
  { id: "providers", title: "Providers", summary: "Proxy providers, rule providers, health checks and update actions." },
  { id: "logs", title: "Logs", summary: "Engine logs and filtered runtime diagnostics." },
  { id: "connections", title: "Connections", summary: "Live connection list, close-all action and traffic visibility." },
  { id: "rules", title: "Rules", summary: "Rule matching visibility and router/provider diagnostics." },
  { id: "settings", title: "Settings", summary: "Shell settings, startup, credentials and diagnostics." },
  { id: "feedback", title: "Feedback", summary: "About, updates and build references." },
];

/// Preference defaults, matching `UiPreferences::default()`. They are replaced
/// by the real snapshot during bootstrap; nothing else is ever assumed.
export const defaultSettings = {
  theme: "system",
  font_family: "",
  retain_window_bounds: true,
  launch_at_login: false,
  silent_start: false,
  check_for_updates: false,
};

export const defaultSettingsSnapshot = {
  persisted: false,
  settings: { ...defaultSettings },
};

export const THEME_OPTIONS = [
  { value: "system", label: "System" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

/// `FontFamily` is a closed enum in the preference store, so the dashboard
/// offers exactly the values the backend accepts instead of free text that
/// would be rejected on save.
export const FONT_OPTIONS = [
  { value: "", label: "System" },
  { value: "Avenir Next", label: "Avenir Next" },
  { value: "SF Mono", label: "SF Mono" },
];

export const defaultEngineStatus = {
  desiredMode: "off",
  state: "Off",
  mode: "off",
  active: false,
  systemProxyActive: false,
  tunnelActive: false,
  systemProxyAvailable: false,
  tunnelAvailable: false,
  availabilityReason: null,
  cutoverReady: false,
  cutoverReason: null,
  generation: 0,
  configDigest: null,
};

export const state = {
  payload: { product: { name: "Clash for Mac", version: null } },
  settingsSnapshot: defaultSettingsSnapshot,
  platform: null,
  // Engine status envelope (`engine_snapshot`), validated against its runtime
  // identity before it is allowed to claim an active data plane.
  engine: { ...defaultEngineStatus },
  // Renderer-side feedback only. Rust admission remains the correctness
  // boundary for duplicate shortcuts, direct IPC, and multiple webviews.
  engineMutationBusy: false,
  // Whether this process is the controlled `--migration-handoff` instance,
  // read from `boot_payload`. The default (main) dashboard offers the restart
  // that enters the handoff; only the handoff instance drives the cutover.
  migrationHandoff: false,
  // Latest validated `legacy_retirement_status` (`{ state, ... }`). An IPC or
  // schema failure becomes the explicit local `unverifiable` state; it is
  // never represented as an ordinary absence or a cleared migration.
  retirement: null,
  // In-flight cutover progress within the handoff instance.
  cutover: {
    busy: false,
    target: "system_proxy",
    awaitingApproval: false,
    message: null,
    receiptId: null,
    receiptTarget: null,
    receiptIssuedAt: null,
    receiptExpiresAt: null,
    confirmedReceiptId: null,
    dnsReviewedReceiptId: null,
  },
  // Values read out of the projected engine configuration. Null means the
  // projection could not be read, never a placeholder port or endpoint.
  projection: { mixedPort: null, controller: null, logLevel: null, error: null },
  networkDiagnostics: null,
  activePage: "general",
  mode: "Rule",
  logLevel: null,
  proxyFilter: "",
  activeProxyGroup: null,
  collapsedProxyGroups: new Set(),
  logFilter: "all",
  logSearch: "",
  logsPaused: false,
  connectionSearch: "",
  ruleSearch: "",
  connectionSort: "age",
  connectionSortDesc: false,
  connectionPaused: false,
  connectionDetailId: null,
  closingConnectionIds: new Set(),
  closingAllConnections: false,
  lastRefresh: "Just now",
  controllerStatus: "controller offline",
  toggles: {
    systemProxy: false,
    tunMode: false,
    // Projection-bound switches. They can only be off in this build and are
    // rendered disabled with the backend's own reason.
    allowLan: false,
    mixin: false,
    startAtLogin: false,
    silentStart: false,
    checkForUpdates: false,
    retainWindowBounds: true,
    // Session-only view options. They are not persisted because the 0.4.0
    // preference store has no field for them.
    breakOnProxyChange: true,
    testingDelays: false,
    hideUnavailable: false,
    showProxyFilter: true,
    showProxiesList: true,
    showProcess: true,
  },
  proxyBlinkNode: null,
  traffic: {
    upload: 0,
    download: 0,
    runtimeSeconds: 0,
  },
  // Wall-clock millis when the engine was first observed active; null when it is
  // not. Drives a real uptime instead of an always-incrementing counter.
  engineStartedAt: null,
  // Live GeoIP status from app home. 0.4.0 consumes no GeoIP database, so this
  // only reports a leftover legacy file.
  geoipStatus: null,
  controllerVersion: null,
  connectionStream: {
    at: 0,
    uploadTotal: 0,
    downloadTotal: 0,
    rows: new Map(),
  },
  profiles: [],
  profileInspector: null,
  /** @type {{ id: string, x: number, y: number } | null} */
  profileContextMenu: null,
  updateInfo: null,
  /** @type {{ kind: string, id?: string, payload?: any } | null} */
  glassDialog: null,
  /** Credential setup for one profile; secrets never enter this object. */
  credentialSetup: null,
  credentialGcPreview: null,
  proxyGroups: [],
  logs: [],
  connections: [],
  providers: [],
  ruleProviders: [],
  providerCapabilityError: null,
  rules: [],
  providerActions: new Set(),
  providerBulkActions: new Set(),
};

export const navInitials = {
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

export const primaryNavIds = new Set(PAGES.map((page) => page.id));
export const MAX_LOG_ROWS = 200;
export const MAX_CONNECTION_ROWS = 500;
export const runtime = {
  renderFrame: null,
  connectionsPatchFrame: null,
  logStreamFrame: null,
  globalEventsBound: false,
  connectionRowEls: null,
  delayTestGeneration: 0,
};
