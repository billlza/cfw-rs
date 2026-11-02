// Validation of the native settings snapshot and the presentation of its
// Login Item (Windows: startup registration) state.
import { state, THEME_OPTIONS } from "./state.js";
import { FONT_OPTIONS } from "./font-preferences.js";
import { t, SUPPORTED_LOCALES, LANGUAGE_OPTIONS } from "./i18n.js";

const LOGIN_ITEM_LIVE_STATUSES = new Set([
  "checking",
  "enabled",
  "registered",
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

export function normalizeSettingsSnapshot(snapshot) {
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

export function normalizeLaunchAtLoginState(snapshot) {
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
  const windows = state.payload?.product?.operating_system === "windows";
  if (windows
    ? !["checking", "registered", "not_registered"].includes(value.live_status)
    : value.live_status === "registered") {
    throw new TypeError("startup status does not belong to the current platform");
  }
  if (typeof value.matches_persisted_intent !== "boolean") {
    throw new TypeError("Login Item synchronization flag is not boolean");
  }
  if (value.persisted_intent !== snapshot.settings.launch_at_login) {
    throw new TypeError("Login Item persisted intent disagrees with settings");
  }
  const expectedMatch = value.live_status === "enabled" || value.live_status === "registered"
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

export function launchAtLoginPresentation() {
  if (state.settingsUnavailableReason) {
    return {
      hint: state.settingsUnavailableReason,
      reason: state.settingsUnavailableReason,
    };
  }
  const value = state.launchAtLogin;
  const windows = state.payload?.product?.operating_system === "windows";
  if (value.observationError) {
    return { hint: value.observationError, reason: value.observationError };
  }
  if (value.liveStatus === "checking") {
    const reason = windows ? t("Checking Windows startup registration…") : t("Checking macOS Login Item status…");
    return { hint: reason, reason };
  }
  if (value.liveStatus === "unknown") {
    const reason = windows
      ? t("Windows startup registration could not be verified. Reload to retry.")
      : t("Start at Login is unavailable because macOS returned an unknown Login Item state.");
    return { hint: reason, reason };
  }
  if (windows) {
    if (value.liveStatus === "registered") {
      return {
        hint: value.matchesPersistedIntent
          ? t("Registered for this user's sign-in. Windows Startup settings can disable or delay launch; registration does not confirm launch.")
          : t("Windows has a startup registration while the saved preference says Off. Switching Off removes the registration."),
        reason: null,
      };
    }
    if (value.liveStatus === "not_registered") {
      return {
        hint: value.matchesPersistedIntent
          ? t("No startup registration for this user; the saved preference is Off.")
          : t("The saved preference says On, but the Windows startup registration is absent. Switching On retries registration."),
        reason: null,
      };
    }
    const reason = t("Windows startup registration could not be verified. Reload to retry.");
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
