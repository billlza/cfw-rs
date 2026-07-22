export const NAV_ITEMS = Object.freeze([
  { id: "general", title: "General", summary: "Engine mode and verified network state" },
  { id: "profiles", title: "Profiles", summary: "Validated typed proxy profiles" },
  { id: "settings", title: "Settings", summary: "Application preferences" },
  { id: "logs", title: "Logs", summary: "Bounded application and engine events" },
  { id: "about", title: "About", summary: "Version and signed update status" },
]);

export const NAV_IDS = new Set(NAV_ITEMS.map(({ id }) => id));
export const MAX_LOG_ROWS = 300;

export function initialState() {
  return {
    activePage: "general",
    product: null,
    settingsSnapshot: null,
    profiles: [],
    profileCredentialSetup: null,
    credentialGcPreview: null,
    cutoverPreparation: null,
    updateInfo: null,
    engine: {
      mode: "off",
      desiredMode: "off",
      state: "Off",
      systemProxyActive: false,
      tunnelActive: false,
      systemProxyAvailable: false,
      tunnelAvailable: false,
      cutoverReady: false,
      cutoverReason: "The signed native replacement has not passed cutover preflight.",
      availabilityReason: "The signed native engine bridge has not reported capability.",
      tunnelReason: "The native packet tunnel has not reported readiness.",
      generation: null,
      configDigest: null,
    },
    legacyRetirement: {
      state: "awaiting_confirmation",
      action: null,
      message: "The existing VPN remains untouched until an explicit, preflighted cutover.",
    },
    logs: [],
    busyAction: null,
    fatalError: null,
    lastRefreshAt: null,
  };
}
