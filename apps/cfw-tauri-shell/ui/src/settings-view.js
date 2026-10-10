import { t, LANGUAGE_OPTIONS } from "./i18n.js";
// Settings and read-only network diagnostics rendering. Commands and
// transactional settings dialogs own all mutations.
export function createSettingsView({ state, defaultSettingsSnapshot, defaultSettings, engineIsOff, launchAtLoginPresentation, escapeHtml, renderToggle, THEME_OPTIONS, FONT_OPTIONS, REASONS, engineStateLabel, serviceProxyLabel }) {
function renderSettingsGroup(title, rows) {
  return `
    <section class="panel settings-group">
      <div class="section-heading">
        <div>
          <p class="label">${escapeHtml(t("Settings"))}</p>
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
        ${options.map((option) => `<option value="${escapeHtml(option.value)}" ${option.value === value ? "selected" : ""}>${escapeHtml(t(option.label))}</option>`).join("")}
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
    : t("unavailable");
  return `
    <div class="settings-layout">
      <section class="panel toolbar-panel settings-toolbar">
        <div>
          <p class="label">${escapeHtml(t("Preferences"))}</p>
          <h3>${settingsReason ? t("Preferences unavailable") : snapshot.persisted ? t("Preferences saved") : t("Default preferences")}</h3>
          <p class="muted">${escapeHtml(settingsReason ?? t("Save appearance and startup preferences here. Network and background controls apply in their own dialogs."))}</p>
        </div>
        <div class="toolbar-actions">
          <button class="button ghost danger" data-action="reset-settings" ${settingsReason ? `disabled title="${escapeHtml(settingsReason)}"` : ""}>${escapeHtml(t("Reset Preferences"))}</button>
          <button class="button" data-action="save-settings" ${settingsReason ? `disabled title="${escapeHtml(settingsReason)}"` : ""}>${escapeHtml(t("Save Preferences"))}</button>
          <button class="button ghost" data-action="reload-settings">${escapeHtml(t("Reload From Disk"))}</button>
          <button class="button ghost" data-action="force-quit-app">${escapeHtml(t("Force Quit"))}</button>
          <button class="button ghost" data-action="quit-app">${escapeHtml(t("Quit"))}</button>
        </div>
      </section>

      ${renderSettingsGroup(t("General"), [
        renderToggle("startAtLogin", t("Start at Login"), launchAtLogin.hint, { reason: launchAtLogin.reason }),
        renderToggle("silentStart", t("Silent Start"), t("Start hidden in the menu bar without a Dock icon."), { reason: settingsReason }),
        renderToggle("checkForUpdates", t("Check for updates"), t("Check GitHub for a newer official release at launch."), { reason: settingsReason }),
        renderToggle("retainWindowBounds", t("Retain window bounds"), t("Restore the dashboard window position between launches."), { reason: settingsReason }),
        renderSettingAction(t("Updates"), "GitHub Releases", t("Check the official release feed now."), "check-for-updates", t("Check for Updates")),
      ])}

      ${renderSettingsGroup(t("Appearance"), [
        renderSettingSelect(t("Language"), persisted.language, LANGUAGE_OPTIONS, t("Applied immediately and saved. Follow system uses your macOS language preferences."), "data-language-setting", settingsReason),
        renderSettingSelect(t("Theme"), persisted.theme ?? "system", THEME_OPTIONS, t("Applied immediately and persisted."), "data-theme-setting", settingsReason),
        renderSettingSelect(t("Font"), persisted.font_family ?? "", FONT_OPTIONS, t("The preference store accepts these families only."), "data-font-family", settingsReason),
      ])}

      ${renderSettingsGroup(t("Engine"), [
        renderSettingAction(t("Local proxy port"), state.runtimeSettings?.effective.mixed_port ?? listenAddress, t("Configure local port, log level, TUN MTU and LAN access."), "open-runtime-settings", t("Configure"), state.runtimeSettingsError),
        renderSettingValue(t("Controller"), projection.controller ?? "not running", t("App-owned loopback controller of the running engine. Its secret is never shown.")),
        renderSettingValue(t("Engine state"), t("{state} · desired {desiredMode}", { state: engineStateLabel(engine), desiredMode: engine.desiredMode }), engine.availabilityReason ?? t("Live state of the Authority-mediated engine.")),
        renderSettingValue(t("Log level"), projection.logLevel ?? "info", REASONS.logLevel),
        renderToggle("allowLan", t("Allow LAN"), REASONS.allowLan, { reason: state.runtimeSettingsError, disabled: state.engineMutationBusy }),
        renderToggle("mixin", t("Mixin"), "", { reason: REASONS.mixin }),
      ])}

      ${renderSettingsGroup(t("Background controls"), [
        renderSettingAction(t("Shortcuts & network rules"), t("Global shortcuts and automatic connection"), t("Choose global hotkeys and opt-in rules for Wi-Fi or wired networks."), "open-automation-settings", t("Configure")),
      ])}

      ${renderSettingsGroup(t("Proxies"), [
        renderToggle("hideUnavailable", t("Hide timed-out proxies"), t("Hide nodes that failed the latency test. Session only: this build persists no view options.")),
        renderSettingValue(t("Delay test target"), t("controlled HTTPS"), t("No delay-test URL preference exists in this build; probes use the fixed HTTPS connectivity target.")),
      ])}

      ${renderSettingsGroup(t("Connections"), [
        renderToggle("breakOnProxyChange", t("Break connections"), t("Close open connections after a proxy, mode or profile change. Session only.")),
        renderToggle("showProcess", t("Show Process"), t("Show the process name the engine reports for a connection. Session only.")),
      ])}

      ${renderSettingsGroup(t("Credentials"), [
        renderSettingValue(t("Profile credentials"), t("Keychain vault"), t("A profile references secrets by immutable id only. Open a profile's context menu → Credentials to store missing values.")),
        renderSettingAction(
          t("Unused credentials"),
          t("Vault cleanup"),
          t("Review Keychain entries that no stored profile references."),
          "preview-credential-gc",
          t("Review"),
          engineOff ? null : REASONS.engineNotOff,
        ),
      ])}

      ${renderSettingsGroup(t("Legacy maintenance"), [
        renderSettingAction(
          t("Older Clash for Mac"),
          t("Optional"),
          t("Review cleanup of older CFM components and managed data, or recover an unfinished operation. Normal System Proxy and TUN starts are independent of cleanup."),
          "open-legacy-maintenance",
          t("Open maintenance"),
        ),
      ])}

      ${renderSettingsGroup(t("Paths"), [
        renderSettingAction(t("Home Directory"), t("Application Support"), t("Open the application home directory in Finder."), "open-home-directory", t("Open Folder")),
        renderSettingAction(t("Logs"), "logs", t("Open the log directory in Finder."), "reveal-logs", t("Open Folder")),
      ])}

      ${renderSettingsGroup("DNS", [
        renderSettingAction(t("System DNS"), t("never written"), REASONS.restoreDns, "tun-restore-dns-info", t("Details")),
      ])}

      ${renderSettingsGroup(t("Cache"), [
        renderSettingAction(t("Fake IP Cache"), t("Controller-backed"), t("Flush the engine fake-ip cache."), "flush-fake-ip-cache", t("Flush")),
      ])}

      ${platform ? renderSettingsGroup("macOS", [
        renderSettingValue(t("Minimum macOS"), platform.minimum_macos ?? "15.0", t("ARM64-only app baseline.")),
        renderSettingValue(t("Intel support"), platform.intel_supported ? t("Enabled") : t("Disabled"), t("Removed to keep the Apple Silicon runtime lean.")),
        renderSettingValue(t("System proxy"), t(platform.system_proxy_strategy ?? ""), t("How the system proxy is applied.")),
        renderSettingValue(t("Tunnel"), t(platform.tun_strategy ?? ""), t("How the packet tunnel runs.")),
        renderSettingValue(t("Helper"), t(platform.helper_strategy ?? ""), t("Privileged helper strategy.")),
        renderSettingValue("launchd", t(platform.launchd_strategy ?? ""), t("No product-layer ad-hoc scripts.")),
      ]) : renderSettingsGroup("macOS", [
        renderSettingValue(t("Platform design"), t("Unavailable"), t("The platform design could not be read.")),
      ])}

      ${renderNetworkDiagnostics()}
    </div>
  `;
}

function renderNetworkDiagnostics() {
  const diagnostics = state.networkDiagnostics;
  if (!diagnostics) {
    return renderSettingsGroup(t("Network Diagnostics"), [
      renderSettingValue(t("Services"), t("Unavailable"), "macOS network services could not be observed."),
    ]);
  }
  const services = diagnostics.services ?? [];
  const proxied = diagnostics.proxied_services ?? [];
  const unavailable = diagnostics.unavailable ?? [];
  const rows = [
    renderSettingValue(
      t("Service order"),
      services.length ? t("{count} service(s)", { count: services.length }) : "none",
      t("Read from SystemConfiguration only; no child process is spawned."),
    ),
    renderSettingValue(
      t("Services carrying a proxy"),
      proxied.length ? proxied.join(", ") : "none",
      t("Any service with a proxy setting enabled, whoever owns it. Ownership is not reported."),
    ),
    ...services.map((service) => renderSettingValue(
      service.display_name ?? service.service_id ?? t("unknown"),
      serviceProxyLabel(service),
      t("set order {value1}", { value1: service.order ?? "-" }),
    )),
  ];
  if (unavailable.length) {
    rows.push(renderSettingValue(
      t("Unavailable fields"),
      unavailable.join(", "),
      t("Reported unavailable by the backend: the child-process tools that produced them are retired."),
    ));
  }
  return renderSettingsGroup(t("Network Diagnostics"), rows);
}


return {renderSettings,renderNetworkDiagnostics};
}
