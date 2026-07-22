import { button, heading, node, settingRow, statusPill } from "../dom.js";

function engineTone(engine) {
  if (engine.state === "Failed") return "error";
  if (engine.mode === "off") return "neutral";
  return "good";
}

function modeButton(label, mode, state) {
  const active = state.engine.desiredMode === mode;
  const unavailable = mode === "tunnel"
    ? !state.engine.tunnelAvailable
    : mode === "system-proxy"
      ? !state.engine.systemProxyAvailable
      : false;
  return button(label, "set-engine-mode", {
    className: `button ${active ? "active" : "ghost"}`,
    disabled: Boolean(state.busyAction) || unavailable || (mode !== "off" && state.legacyRetirement.state !== "cleared"),
    dataset: { mode },
  });
}

export function renderGeneralPage(state) {
  const engine = state.engine;
  const displayedMode = engine.mode === "off" && engine.state !== "Off" ? engine.desiredMode : engine.mode;
  const modeLabel = displayedMode === "system-proxy" ? "System Proxy" : displayedMode === "tunnel" ? "Tunnel" : "Off";
  const status = node("section", { className: "panel hero-panel" }, [
    heading("Engine", modeLabel, "Mode is derived from native state, not from the requested toggle value."),
    node("div", { className: "toolbar-actions" }, [
      statusPill(engine.state, engineTone(engine)),
      button("Refresh", "reload", { className: "button ghost", disabled: Boolean(state.busyAction) }),
    ]),
  ]);

  const modePanel = node("section", { className: "panel" }, [
    heading("Network Mode", "One engine at a time", "System Proxy and Packet Tunnel are mutually exclusive and every switch passes through Off."),
    node("div", { className: "engine-mode-picker" }, [
      modeButton("Off", "off", state),
      modeButton("System Proxy", "system-proxy", state),
      modeButton("Packet Tunnel", "tunnel", state),
    ]),
  ]);

  const tunnelStatus = engine.tunnelAvailable
    ? (engine.tunnelActive ? "Connected and provider-ready" : "Available")
    : "Unavailable";
  const facts = node("section", { className: "panel settings-group" }, [
    heading("Verified State", "Native observations", "Tunnel is Active only after provider readiness and native connection state agree."),
    node("div", { className: "settings-list" }, [
      settingRow("System Proxy", "Observed macOS proxy state", statusPill(engine.systemProxyActive ? "Active" : "Off", engine.systemProxyActive ? "good" : "neutral")),
      settingRow("Packet Tunnel", engine.tunnelReason, statusPill(tunnelStatus, engine.tunnelActive ? "good" : "neutral")),
      settingRow("Configuration", "Generation and digest must match the running provider", node("code", { text: engine.configDigest ? `#${engine.generation ?? "?"} ${engine.configDigest}` : "No verified generation" })),
    ]),
  ]);

  const selectedProfileReady = state.profiles.some((profile) => profile.active);
  const replacementCapabilityReady = engine.cutoverReady;
  const preparation = state.cutoverPreparation;
  const preparationMessage = preparation?.status === "ready"
    ? `Prepared ${preparation.target}; final confirmation is valid for at most ${Math.ceil(preparation.validForMillis / 1000)} seconds.`
    : preparation?.status === "awaiting-approval"
      ? "System Extension approval is pending. Approve it in System Settings, then prepare the same target again."
      : "Choose a target and prepare it while the existing VPN remains untouched.";
  const cutoverMessage = [
    state.legacyRetirement.message,
    !selectedProfileReady ? "Select a staged replacement profile before cutover." : null,
    !replacementCapabilityReady ? engine.cutoverReason : null,
  ].filter(Boolean).join(" ");
  const cleanup = node("section", { className: "panel warning-panel" }, [
    heading("Safe Cutover", `Legacy network: ${state.legacyRetirement.state}`, `${cutoverMessage} ${preparationMessage}`),
    node("div", { className: "toolbar-actions" }, [
      button("Prepare System Proxy", "prepare-legacy-cutover", {
        className: "button ghost",
        disabled: Boolean(state.busyAction)
          || state.legacyRetirement.state === "cleaning"
          || state.legacyRetirement.state === "cleared"
          || state.legacyRetirement.state === "post_cutover_cleanup_required"
          || !selectedProfileReady
          || !engine.systemProxyAvailable
          || engine.state !== "Off",
        dataset: { mode: "system-proxy" },
      }),
      button("Prepare Packet Tunnel", "prepare-legacy-cutover", {
        className: "button ghost",
        disabled: Boolean(state.busyAction)
          || state.legacyRetirement.state === "cleaning"
          || state.legacyRetirement.state === "cleared"
          || state.legacyRetirement.state === "post_cutover_cleanup_required"
          || !selectedProfileReady
          || !engine.tunnelAvailable
          || engine.state !== "Off",
        dataset: { mode: "tunnel" },
      }),
    ]),
    button("Cut Over from Legacy Network", "cleanup-legacy", {
      className: "button danger",
      disabled: Boolean(state.busyAction)
        || state.legacyRetirement.state === "cleaning"
        || state.legacyRetirement.state === "cleared"
        || state.legacyRetirement.state === "post_cutover_cleanup_required"
        || !selectedProfileReady
        || !replacementCapabilityReady
        || preparation?.status !== "ready",
    }),
  ]);

  return node("div", { className: "general-layout" }, [status, modePanel, facts, cleanup]);
}
