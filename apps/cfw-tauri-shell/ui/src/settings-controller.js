// The renderer-owned preferences: reading and applying the native settings
// snapshot, the appearance it selects, and resetting it.
import { state, defaultSettings, defaultSettingsSnapshot, THEME_OPTIONS } from "./state.js";
import { errorText, escapeHtml } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t, setLocale, getLocale, LANGUAGE_OPTIONS } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { FONT_OPTIONS, platformFontStyles } from "./font-preferences.js";
import { normalizeSettingsSnapshot, normalizeLaunchAtLoginState } from "./settings-snapshot.js";

export function createSettingsController({ windowGlass, renderPage, renderGlassOverlays, loadProfilesSnapshot, closeGlassDialog }) {
  /// Applies a `SettingsSnapshot`. The preference store holds exactly seven
  /// renderer-owned fields; everything the 0.3.5 file used to carry now lives in
  /// the projected engine configuration and is read, never written, from there.
  function applyPersistedSettings(snapshot) {
    const settings = normalizeSettingsSnapshot(snapshot);
    const launchAtLogin = normalizeLaunchAtLoginState(snapshot);
    state.settingsSnapshot = snapshot;
    state.settingsUnavailableReason = null;
    state.launchAtLogin = launchAtLogin;
    state.toggles.startAtLogin = launchAtLogin.liveStatus === "enabled"
      || launchAtLogin.liveStatus === "registered"
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

  /// The seven renderer-owned preference fields, and nothing else: the preference
  /// store rejects an unknown field, and `launch_at_login` may only be changed by
  /// the transactional Login Item command, so it is echoed back unchanged.
  function persistedSettingsFromUi() {
    const current = state.settingsSnapshot?.settings ?? defaultSettings;
    const theme = document.querySelector("[data-theme-setting]")?.value ?? current.theme ?? "system";
    const fontFamily = document.querySelector("[data-font-family]")?.value ?? current.font_family ?? "";
    const language = document.querySelector("[data-language-setting]")?.value ?? current.language;
    if (!LANGUAGE_OPTIONS.some((option) => option.value === language)) throw new TypeError("Invalid language preference");
    if (!FONT_OPTIONS.some((option) => option.value === fontFamily)) throw new TypeError("Invalid font preference");
    return {
      theme: THEME_OPTIONS.some((option) => option.value === theme) ? theme : "system",
      font_family: fontFamily,
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
    windowGlass.refresh();
    for (const [property, value] of Object.entries(platformFontStyles(state.payload.product.operating_system, settings.font_family))) {
      document.documentElement.style.setProperty(property, value);
    }
  }

  function localizeShell() {
    document.querySelectorAll("[data-i18n]").forEach((element) => { element.textContent = t(element.dataset.i18n); });
    const nav = document.getElementById("nav");
    nav?.setAttribute("aria-label", t("Primary navigation"));
    const reload = document.getElementById("reload-button");
    reload?.setAttribute("title", t("Reload dashboard"));
  }

  /// A refused reset keeps its dialog open and is reported in the log.
  async function confirmSettingsReset(dialog) {
    try {
      const snapshot = await invoke("reset_settings_snapshot");
      applyPersistedSettings(snapshot);
      await loadProfilesSnapshot();
      closeGlassDialog(dialog);
      appendLog("warning", "settings", t("Preferences reset to defaults"));
    } catch (error) {
      appendLog("error", "settings", t("Reset failed: {error}", { error: errorText(error) }));
    }
    renderPage();
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
        state.launchAtLogin.observationError = state.payload?.product?.operating_system === "windows"
          ? t("Windows startup registration could not be read. Reload to retry; the failure is recorded in local diagnostics.")
          : "macOS Login Item status could not be read. Reload to retry; the failure is recorded in local diagnostics.";
        appendLog("warning", "settings", state.launchAtLogin.observationError);
      }
    }
    if (["general", "settings"].includes(state.activePage)) renderPage();
  }

  const actions = {
    "save-settings": async () => {
      if (state.settingsUnavailableReason) throw new Error(state.settingsUnavailableReason);
      const snapshot = await invoke("write_settings_snapshot", { settings: persistedSettingsFromUi() });
      applyPersistedSettings(snapshot);
      appendLog("info", "settings", t("Preferences saved"));
      renderPage();
    },
    "reload-settings": async () => {
      await loadSettingsSnapshot();
      appendLog("info", "settings", t("Preferences reloaded from disk"));
      renderPage();
    },
    "reset-settings": async () => {
      if (state.settingsUnavailableReason) throw new Error(state.settingsUnavailableReason);
      // WKWebView often swallows window.confirm — use in-app glass dialog.
      state.glassDialog = { kind: "reset-settings" };
      renderGlassOverlays();
    },
  };

  function bindPage() {
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
  }

  function prompt(dialog) {
    return {
      title: t("Reset all settings"),
      message: t("Reset appearance, silent start and update preferences to their defaults? Imported profiles, the selected profile and the Start with macOS registration are all kept."),
      buttons: [
        { id: "cancel", title: t("No"), role: "cancel" },
        { id: "confirm", title: t("Yes"), role: "destructive", activate: () => confirmSettingsReset(dialog) },
      ],
    };
  }

  function renderResetDialog(dialog, profile, prompt) {
    const [cancel, confirm] = prompt.buttons;
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Reset settings"))}">
          <h3>${escapeHtml(prompt.title)}</h3>
          <p class="glass-dialog-copy">${escapeHtml(prompt.message)}</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(cancel.title)}</button>
            <button type="button" class="glass-btn danger" data-glass-reset-confirm>${escapeHtml(confirm.title)}</button>
          </div>
        </div>
      `);
  }

  function bindResetDialog() {
    document.querySelectorAll("[data-glass-reset-confirm]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        await confirmSettingsReset(state.glassDialog);
      });
    });
  }

  return {
    applyPersistedSettings, resetPersistedSettingsToSafeState, persistedSettingsFromUi, loadSettingsSnapshot,
    refreshStartupLoginItemStatus, confirmSettingsReset,
    dialogs: { kinds: ["reset-settings"], prompt, render: renderResetDialog, bind: bindResetDialog },
    actions,
    bindPage,
  };
}
