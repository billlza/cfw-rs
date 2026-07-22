import { invoke } from "./bridge.js";
import { store } from "./store.js";
import { appendLog } from "./streams.js";

const THEMES = new Set(["light", "dark", "system"]);
const FONTS = new Map([
  ["", "system"],
  ["Avenir Next", "avenir"],
  ["SF Mono", "monospace"],
]);
// One-way migration sanitizer: these names are removed from persisted settings
// and never rendered, executed, or forwarded as runtime configuration.
const REMOVED_KEYS = new Set([
  "mixin",
  "mixin_yaml",
  "mixinYaml",
  "profile_parser_script",
  "profileParserScript",
  "tray_script",
  "trayScript",
  "child_process_command",
  "childProcessCommand",
  "usePacScript",
  "use_pac_script",
  "pacScript",
  "pac_script",
  "coreKind",
  "core_kind",
]);

function applyAppearance(settings) {
  const requestedTheme = THEMES.has(settings.theme) ? settings.theme : "system";
  const resolvedTheme = requestedTheme === "system"
    ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : requestedTheme;
  document.documentElement.dataset.theme = resolvedTheme;
  const font = typeof settings.font_family === "string" ? settings.font_family.trim() : "";
  document.documentElement.dataset.font = FONTS.get(font) ?? "system";
}

export function acceptSettingsSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || !snapshot.settings || typeof snapshot.settings !== "object") {
    throw new TypeError("Native settings snapshot is invalid");
  }
  store.update({ settingsSnapshot: snapshot });
  applyAppearance(snapshot.settings);
  return snapshot;
}

export async function loadSettings() {
  return acceptSettingsSnapshot(await invoke("read_settings_snapshot"));
}

function validatePreferences(input) {
  const theme = String(input.theme ?? "system");
  if (!THEMES.has(theme)) throw new TypeError("Unsupported theme preference");
  const fontFamily = String(input.fontFamily ?? "").trim();
  if (!FONTS.has(fontFamily)) throw new TypeError("Unsupported font preference");
  return {
    theme,
    font_family: fontFamily,
    retain_window_bounds: Boolean(input.retainWindowBounds),
    launch_at_login: Boolean(input.launchAtLogin),
    silent_start: Boolean(input.silentStart),
    check_for_updates: Boolean(input.checkForUpdates),
  };
}

function withoutRetiredFeatures(settings) {
  const safe = { ...settings };
  for (const key of REMOVED_KEYS) delete safe[key];
  return safe;
}

export async function savePreferences(input) {
  let snapshot = store.get().settingsSnapshot;
  if (!snapshot?.settings) throw new TypeError("Settings must be loaded before they can be saved");
  const preferences = validatePreferences(input);
  let loginItemChanged = false;
  if (snapshot.settings.launch_at_login !== preferences.launch_at_login) {
    snapshot = acceptSettingsSnapshot(await invoke("set_launch_at_login_enabled", {
      enabled: preferences.launch_at_login,
    }));
    loginItemChanged = true;
  }
  const nextSettings = { ...withoutRetiredFeatures(snapshot.settings), ...preferences };
  let saved;
  try {
    saved = await invoke("write_settings_snapshot", { settings: nextSettings });
  } catch (error) {
    if (loginItemChanged) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`Login Item was updated, but remaining preferences were not saved: ${detail}`, { cause: error });
    }
    throw error;
  }
  acceptSettingsSnapshot(saved);
  appendLog("info", "settings", "Application preferences saved");
  return saved;
}
