// General page rendering has no native side effects. Runtime controls use the
// same transaction commands as the settings page.
export function createGeneralView({ state, escapeHtml, engineStateLabel, engineToggleCapability, launchAtLoginPresentation, modeHasTunnel, modeHasSystemProxy, renderMigrationBanner, renderRowReason, renderCatLogo, generalIconButton, renderRowNote, renderInlineSwitch, tunnelValueLabel, systemProxyValueLabel, REASONS, RUNTIME_LOG_LEVELS }) {
  return function renderGeneral() {
  const product = state.payload.product;
  const appVersion = product.version ?? "—";
  const update = state.updateInfo;
  const updateBadge = update?.available && update?.version
    ? `<button type="button" class="cfw-update-badge" data-action="check-for-updates" title="Update available — click to download">→ v${escapeHtml(String(update.version))}</button>`
    : "";
  const engine = state.engine;
  const projection = state.projection;
  const settingsView = state.runtimeSettings;
  const settingsReason = state.migrationHandoff ? "Finish migration before changing network settings" : state.runtimeSettingsError ?? (!settingsView ? "Network settings are loading" : null);
  const statusDot = engine.active ? "cfw-status-dot on" : "cfw-status-dot";
  const localPort = projection.mixedPort ?? settingsView?.effective.mixed_port;
  const listenAddress = localPort ? `127.0.0.1:${localPort}` : null;
  const lan = settingsView?.settings.allow_lan ? settingsView.settings.lan_proxy : null;
  const bind = lan ? `${lan.listen}:${lan.port}` : "Off";
  const logLevel = settingsView?.effective.log_level ?? projection.logLevel ?? state.logLevel ?? "info";
  const engineLabel = state.controllerVersion?.version
    ? `sing-box · ${state.controllerVersion.version}`
    : `sing-box · ${engineStateLabel(engine)}`;
  const tunnelCapability = engineToggleCapability("tunMode");
  const proxyCapability = engineToggleCapability("systemProxy");
  const tunnelReason = tunnelCapability.available ? null : tunnelCapability.reason;
  const proxyReason = proxyCapability.available ? null : proxyCapability.reason;
  const tunnelRetryDisabled = state.engineMutationBusy || !tunnelCapability.available ? " disabled" : "";
  const proxyRetryDisabled = state.engineMutationBusy || !proxyCapability.available ? " disabled" : "";
  const launchAtLogin = launchAtLoginPresentation();
  const tunnelRecoveryAction = engine.state === "AwaitingApproval"
    ? `<button class="cfw-text-button" data-action="retry-tun-mode"${tunnelRetryDisabled}>Approve…</button>`
    : engine.state === "Failed" && modeHasTunnel(engine.desiredMode)
      ? `<button class="cfw-text-button" data-action="retry-tun-mode"${tunnelRetryDisabled}>Retry</button>`
      : "";
  const proxyRecoveryAction = engine.state === "Failed" && modeHasSystemProxy(engine.desiredMode)
    ? `<button class="cfw-text-button" data-action="retry-system-proxy"${proxyRetryDisabled}>Retry</button>`
    : "";
  const cancellationDisabled = state.engineMutationBusy || state.migrationHandoff ? " disabled" : "";
  const tunnelCancellationAction = modeHasTunnel(engine.desiredMode) && !engine.tunnelActive
    ? `<button class="cfw-text-button" data-action="cancel-tun-mode"${cancellationDisabled}>Cancel request</button>`
    : "";
  const proxyCancellationAction = modeHasSystemProxy(engine.desiredMode) && !engine.systemProxyActive
    ? `<button class="cfw-text-button" data-action="cancel-system-proxy"${cancellationDisabled}>Cancel request</button>`
    : "";
  const migrationBanner = renderMigrationBanner();
  const engineReason = state.engineMutationError ?? engine.availabilityReason;
  return `
    <div class="cfw-general-view">
      <section class="cfw-header">
        <div class="cfw-app-mark">${renderCatLogo()}</div>
        <div class="cfw-title">
          <span>Clash for Mac</span>
          <small>v${escapeHtml(appVersion)}${updateBadge}</small>
        </div>
      </section>

      <section class="cfw-content${migrationBanner ? " cfw-content-migration" : ""}">
        ${migrationBanner}
        ${engineReason ? renderRowReason(engineReason) : ""}
        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Port</span>
            <span class="general-icons">
              ${generalIconButton("copy-proxy-exports", "terminal", "Copy proxy export commands for Terminal")}
            </span>
          </div>
          <div class="cfw-row-right">
            <button type="button" class="cfw-text-button" data-action="open-runtime-settings"${settingsReason || state.engineMutationBusy ? " disabled" : ""}>${escapeHtml(listenAddress ?? "unavailable")}</button>
            ${renderRowNote(settingsView?.settings.preferred_mixed_port === null ? "Automatic port" : "Configured port", settingsReason ?? "Click to change the local proxy port, log level, MTU or LAN sharing.")}

          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Allow LAN</span>
            <span class="general-icons">
              ${generalIconButton("allow-lan-info", "info", REASONS.allowLan)}
              ${generalIconButton("show-network-interfaces", "device-hub", "network interfaces")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value" title="${escapeHtml(REASONS.bindAddress)}">Bind: ${escapeHtml(bind)}</span>
            ${renderRowNote(lan ? "Trusted sources only" : "Local devices only", settingsReason ?? REASONS.allowLan)}
            ${renderInlineSwitch("allowLan", "Allow LAN", { reason: settingsReason, disabled: state.engineMutationBusy })}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Log Level</div>
          <div class="cfw-row-right">
            <select class="cfw-select" data-runtime-log-level aria-label="Engine log level"${settingsReason || state.engineMutationBusy ? " disabled" : ""}>
              ${RUNTIME_LOG_LEVELS.map((level) => `<option value="${level}"${level === logLevel ? " selected" : ""}>${level}</option>`).join("")}
            </select>
            ${renderRowNote("Applied and saved", settingsReason ?? REASONS.logLevel)}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Engine</span>
            <span class="general-icons">
              ${generalIconButton("preview-runtime-config", "memory", "Preview the projected configuration this engine runs")}
              ${generalIconButton("dns-query", "dns", "Resolve a host through the running engine")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value core-version-link" title="${escapeHtml(projection.controller ? `app-owned controller ${projection.controller}` : "the controller exists only while an engine is running")}">
              <i class="${statusDot}"></i>
              <span>${escapeHtml(engineLabel)}</span>
            </span>
            <button class="cfw-text-button" data-action="toggle-core" ${state.engineMutationBusy || state.migrationHandoff ? "disabled" : ""}>${engine.desiredMode === "off" ? "Start core" : "Stop core"}</button>
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">TUN MTU</div>
          <div class="cfw-row-right"><button type="button" class="cfw-text-button" data-action="open-runtime-settings"${settingsReason || state.engineMutationBusy ? " disabled" : ""}>${escapeHtml(String(settingsView?.effective.tunnel_mtu ?? "unavailable"))}</button></div>
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
            <span class="cfw-link-value">${escapeHtml(state.savedProfilePolicy?.geoipCountries.join(", ") || "No country rules configured")}</span>
            ${renderRowNote("Automatic updates", REASONS.geoip)}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>TUN Mode</span>
            <span class="general-icons">
              ${generalIconButton("tun-info", "info", "The Packet Tunnel runs as a signed NetworkExtension System Extension and must be approved once in System Settings.")}
              ${generalIconButton("tun-restore-dns-info", "history", "System DNS after TUN Mode is disabled")}
            </span>
          </div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${escapeHtml(tunnelValueLabel(engine))}</span>
            ${tunnelRecoveryAction}
            ${tunnelCancellationAction}
            ${tunnelReason ? renderRowNote("Unavailable", tunnelReason) : ""}
            ${renderInlineSwitch("tunMode", "TUN Mode", {
              reason: tunnelReason,
              disabled: state.engineMutationBusy,
              allowDisableWhenUnavailable: !state.migrationHandoff,
            })}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">
            <span>Mixin</span>
            <span class="general-icons">
              ${generalIconButton("mixin-info", "info", REASONS.mixin)}
            </span>
          </div>
          <div class="cfw-row-right">
            ${renderRowNote("Unavailable", REASONS.mixin)}
            ${renderInlineSwitch("mixin", "Mixin", { reason: REASONS.mixin })}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">System Proxy</div>
          <div class="cfw-row-right">
            <span class="cfw-link-value">${escapeHtml(systemProxyValueLabel(engine))}</span>
            ${proxyRecoveryAction}
            ${proxyCancellationAction}
            ${proxyReason ? renderRowNote("Unavailable", proxyReason) : ""}
            ${renderInlineSwitch("systemProxy", "System Proxy", {
              reason: proxyReason,
              disabled: state.engineMutationBusy,
              allowDisableWhenUnavailable: !state.migrationHandoff,
            })}
          </div>
        </div>

        <div class="cfw-row">
          <div class="cfw-row-left">Start with macOS</div>
          <div class="cfw-row-right">${renderInlineSwitch("startAtLogin", "Start with macOS", { reason: launchAtLogin.reason, title: launchAtLogin.hint })}</div>
        </div>
      </section>
    </div>
  `;
}
;
}
