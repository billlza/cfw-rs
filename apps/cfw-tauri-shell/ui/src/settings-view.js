// Settings and read-only network diagnostics rendering. Commands and
// transactional settings dialogs own all mutations.
export function createSettingsView({ state, defaultSettingsSnapshot, defaultSettings, engineIsOff, launchAtLoginPresentation, escapeHtml, renderToggle, THEME_OPTIONS, FONT_OPTIONS, REASONS, engineStateLabel, serviceProxyLabel }) {
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
          <h3>${settingsReason ? "Preferences unavailable" : snapshot.persisted ? "Preferences saved" : "Default preferences"}</h3>
          <p class="muted">${escapeHtml(settingsReason ?? "Save appearance and startup preferences here. Network and background controls apply in their own dialogs.")}</p>
        </div>
        <div class="toolbar-actions">
          <button class="button ghost danger" data-action="reset-settings" ${settingsReason ? `disabled title="${escapeHtml(settingsReason)}"` : ""}>Reset Preferences</button>
          <button class="button" data-action="save-settings" ${settingsReason ? `disabled title="${escapeHtml(settingsReason)}"` : ""}>Save Preferences</button>
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
        renderSettingAction("Local proxy port", state.runtimeSettings?.effective.mixed_port ?? listenAddress, "Configure local port, log level, TUN MTU and LAN access.", "open-runtime-settings", "Configure", state.runtimeSettingsError),
        renderSettingValue("Controller", projection.controller ?? "not running", "App-owned loopback controller of the running engine. Its secret is never shown."),
        renderSettingValue("Engine state", `${engineStateLabel(engine)} · desired ${engine.desiredMode}`, engine.availabilityReason ?? "Live state of the Authority-mediated engine."),
        renderSettingValue("Log level", projection.logLevel ?? "info", REASONS.logLevel),
        renderToggle("allowLan", "Allow LAN", REASONS.allowLan, { reason: state.runtimeSettingsError, disabled: state.engineMutationBusy }),
        renderToggle("mixin", "Mixin", "", { reason: REASONS.mixin }),
      ])}

      ${renderSettingsGroup("Background controls", [
        renderSettingAction("Shortcuts & network rules", "Global shortcuts and automatic connection", "Choose global hotkeys and opt-in rules for Wi-Fi or wired networks.", "open-automation-settings", "Configure"),
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

      ${renderSettingsGroup("Legacy maintenance", [
        renderSettingAction(
          "Older Clash for Mac",
          "Optional",
          "Review cleanup of older CFM components and managed data, or recover an unfinished operation. Normal System Proxy and TUN starts are independent of cleanup.",
          "open-legacy-maintenance",
          "Open maintenance",
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


return {renderSettings,renderNetworkDiagnostics};
}
