import { button, heading, node, settingRow } from "../dom.js";

function checkbox(name, checked, disabled) {
  return node("input", { type: "checkbox", checked, disabled, attributes: { name } });
}

export function renderSettingsPage(state) {
  const settings = state.settingsSnapshot?.settings ?? {};
  const busy = Boolean(state.busyAction);
  const theme = node("select", { value: settings.theme ?? "system", attributes: { name: "theme" } }, [
    node("option", { text: "System", value: "system" }),
    node("option", { text: "Light", value: "light" }),
    node("option", { text: "Dark", value: "dark" }),
  ]);
  theme.value = settings.theme ?? "system";
  const font = node("select", { value: settings.font_family ?? "", attributes: { name: "fontFamily" } }, [
    node("option", { text: "System", value: "" }),
    node("option", { text: "Avenir Next", value: "Avenir Next" }),
    node("option", { text: "SF Mono", value: "SF Mono" }),
  ]);
  font.value = ["", "Avenir Next", "SF Mono"].includes(settings.font_family) ? settings.font_family : "";
  const form = node("form", { className: "panel settings-group", dataset: { preferencesForm: "true" } }, [
    heading("Preferences", "Application only", "Engine configuration, credentials and scripts are not stored in renderer preferences."),
    node("div", { className: "settings-list" }, [
      settingRow("Theme", "Follow the system or choose a fixed appearance", theme),
      settingRow("Font", "Choose a bundled system font policy", font),
      settingRow("Remember Window", "Restore the last safe window bounds", checkbox("retainWindowBounds", settings.retain_window_bounds !== false, busy)),
      settingRow("Launch at Login", "Use the signed user login item", checkbox("launchAtLogin", settings.launch_at_login === true, busy)),
      settingRow("Silent Start", "Start without showing the main window", checkbox("silentStart", settings.silent_start === true, busy)),
      settingRow("Automatic Update Checks", "Check the signed updater feed", checkbox("checkForUpdates", settings.check_for_updates !== false, busy)),
    ]),
    node("div", { className: "toolbar-actions" }, [button("Save Preferences", "save-preferences", { disabled: busy })]),
  ]);

  return node("div", { className: "settings-layout" }, [form]);
}
