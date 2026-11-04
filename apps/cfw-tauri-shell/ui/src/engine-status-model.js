// The engine status envelope the host reports: its validation and the labels
// the dashboard shows for it.
import { t } from "./i18n.js";
import { redactDiagnosticText } from "./text-format.js";

const ENGINE_STATE_LABELS = Object.freeze({
  off: "Off",
  local_proxy_starting: "LocalProxyStarting",
  local_proxy_active: "LocalProxyActive",
  local_proxy_stopping: "LocalProxyStopping",
  proxy_starting: "ProxyStarting",
  proxy_active: "ProxyActive",
  proxy_stopping: "ProxyStopping",
  tunnel_installing: "TunnelInstalling",
  awaiting_approval: "AwaitingApproval",
  tunnel_starting: "TunnelStarting",
  tunnel_active: "TunnelActive",
  tunnel_system_proxy_active: "TunnelSystemProxyActive",
  tunnel_stopping: "TunnelStopping",
  failed: "Failed",
});

const ENGINE_STATE_TEXT = Object.freeze({
  Off: "Off",
  LocalProxyStarting: "Starting…",
  LocalProxyActive: "Local proxy",
  LocalProxyStopping: "Stopping…",
  ProxyStarting: "Starting…",
  ProxyActive: "On",
  ProxyStopping: "Stopping…",
  TunnelInstalling: "Installing…",
  AwaitingApproval: "Needs approval",
  TunnelStarting: "Starting…",
  TunnelActive: "On",
  TunnelSystemProxyActive: "On",
  TunnelStopping: "Stopping…",
  Failed: "Failed",
});

export function modeHasSystemProxy(mode) {
  return mode === "system-proxy" || mode === "tunnel-system-proxy";
}

export function modeHasTunnel(mode) {
  return mode === "tunnel" || mode === "tunnel-system-proxy";
}

function engineMode(value) {
  if (value === "local_proxy") return "local-proxy";
  if (value === "system_proxy") return "system-proxy";
  if (value === "tunnel") return "tunnel";
  if (value === "tunnel_system_proxy") return "tunnel-system-proxy";
  if (value === "off") return "off";
  throw new TypeError("engine mode is invalid");
}

function normalizeRuntimeIdentity(runtime, expectedOwners, generation, digest) {
  const context = runtime?.context;
  if (runtime?.ready !== true
    || !expectedOwners.includes(runtime.owner)
    || !context
    || typeof context.installation_id !== "string"
    || context.installation_id.length === 0
    || !Number.isSafeInteger(context.config_epoch)
    || context.config_epoch < 1
    || context.generation !== generation
    || typeof runtime.config_digest !== "string"
    || runtime.config_digest.length === 0
    || runtime.config_digest !== digest) {
    throw new TypeError("runtime identity does not match the engine snapshot");
  }
  return Object.freeze({
    owner: runtime.owner,
    context: Object.freeze({
      installation_id: context.installation_id,
      config_epoch: context.config_epoch,
      generation: context.generation,
    }),
    config_digest: runtime.config_digest,
    ready: true,
  });
}

/// Normalizes an `engine_snapshot` envelope.
///
/// An active data plane is only reported when the runtime identity in the
/// snapshot agrees with the snapshot's own generation and configuration digest
/// and reports itself ready, so a malformed or stale payload can never make the
/// dashboard claim the network is up.
/// The coordinator validates the backend's concrete platform before publishing;
/// presentation validates that its closed owner role agrees with the mode.
export function normalizeEngineStatus(value) {
  if (!value || typeof value !== "object" || !value.snapshot || typeof value.snapshot !== "object") {
    throw new TypeError("engine snapshot envelope is invalid");
  }
  const snapshot = value.snapshot;
  const stateTag = snapshot.state?.state;
  if (!ENGINE_STATE_LABELS[stateTag]) throw new TypeError("engine state is invalid");
  if (!Number.isSafeInteger(snapshot.generation) || snapshot.generation < 0) {
    throw new TypeError("engine generation is invalid");
  }
  const configDigest = typeof snapshot.config_digest === "string" ? snapshot.config_digest : null;
  const desiredMode = engineMode(snapshot.desired_mode);
  let mode = "off";
  let runtimeIdentity = null;
  let reason = typeof value.unavailable_reason === "string" && value.unavailable_reason.trim()
    ? redactDiagnosticText(value.unavailable_reason.trim()).slice(0, 512)
    : null;

  if (stateTag === "local_proxy_active" || stateTag === "proxy_active") {
    runtimeIdentity = normalizeRuntimeIdentity(
      snapshot.state.runtime,
      ["proxy_agent", "windows_user_agent"],
      snapshot.generation,
      configDigest,
    );
    mode = stateTag === "local_proxy_active" ? "local-proxy" : "system-proxy";
  } else if (stateTag === "tunnel_active" || stateTag === "tunnel_system_proxy_active") {
    runtimeIdentity = normalizeRuntimeIdentity(
      snapshot.state.runtime,
      ["packet_tunnel_system_extension", "windows_tunnel_service"],
      snapshot.generation,
      configDigest,
    );
    mode = stateTag === "tunnel_system_proxy_active" ? "tunnel-system-proxy" : "tunnel";
  } else if (stateTag === "failed" && typeof snapshot.state.error === "string") {
    reason = redactDiagnosticText(snapshot.state.error).slice(0, 512);
  }

  const capabilities = value.capabilities && typeof value.capabilities === "object" ? value.capabilities : {};
  const cutoverReason = typeof value.cutover_unavailable_reason === "string" && value.cutover_unavailable_reason.trim()
    ? redactDiagnosticText(value.cutover_unavailable_reason.trim()).slice(0, 512)
    : null;
  return {
    desiredMode,
    mode,
    state: ENGINE_STATE_LABELS[stateTag],
    active: mode !== "off",
    systemProxyActive: modeHasSystemProxy(mode),
    localProxyAvailable: capabilities.local_proxy === true,
    tunnelActive: modeHasTunnel(mode),
    systemProxyAvailable: capabilities.system_proxy === true,
    tunnelAvailable: capabilities.tunnel === true,
    // Each integration on its own does not imply their combination.
    tunnelSystemProxyAvailable: capabilities.tunnel_system_proxy === true,
    providerManagementAvailable: capabilities.provider_management === true,
    availabilityReason: reason,
    startupRecoveryAvailable: value.startup_recovery_available === true
      && stateTag === "failed" && desiredMode === "off" && snapshot.state.target === "off",
    cutoverReady: value.cutover_ready === true,
    observationRecheckPending: stateTag === "failed" && snapshot.state.recheck_pending === true,
    cutoverReason,
    generation: snapshot.generation,
    configDigest,
    runtimeIdentity,
  };
}

/// A failed state whose runtime is still leased and being re-observed is a
/// wait, not a verdict.
function failedStateLabel(engine) {
  return t(engine.observationRecheckPending ? "Reconfirming…" : "Failed");
}

export function engineStateLabel(engine) {
  if (engine?.state === "Failed") return failedStateLabel(engine);
  return t(ENGINE_STATE_TEXT[engine?.state] ?? "Unknown");
}

export function systemProxyValueLabel(engine) {
  if (!engine) return t("Unknown");
  if (engine.state === "TunnelSystemProxyActive") return t("On");
  if (engine.desiredMode === "tunnel-system-proxy" && ["TunnelInstalling", "AwaitingApproval", "TunnelStarting", "TunnelStopping"].includes(engine.state)) return t(ENGINE_STATE_TEXT[engine.state]);
  if (["ProxyStarting", "ProxyActive", "ProxyStopping"].includes(engine.state)) {
    return t(ENGINE_STATE_TEXT[engine.state]);
  }
  if (engine.state === "Failed" && modeHasSystemProxy(engine.desiredMode)) return failedStateLabel(engine);
  return t("Off");
}

/// Value shown next to the TUN switch: the tunnel's own lifecycle when it owns
/// the engine, otherwise the plain off state.
export function tunnelValueLabel(engine) {
  if (!engine) return t("Unknown");
  const tunnelStates = ["TunnelInstalling", "AwaitingApproval", "TunnelStarting", "TunnelActive", "TunnelSystemProxyActive", "TunnelStopping"];
  if (tunnelStates.includes(engine.state)) return t(ENGINE_STATE_TEXT[engine.state]);
  if (engine.state === "Failed" && modeHasTunnel(engine.desiredMode)) return failedStateLabel(engine);
  return t("Off");
}

export function summarizeEngineEvent(payload) {
  if (!payload || typeof payload !== "object") return "invalid engine event payload";
  const type = typeof payload.type === "string" ? payload.type : "event";
  const message = typeof payload.message === "string" ? payload.message : "engine state changed";
  return redactDiagnosticText(`${type}: ${message}`).slice(0, 2048);
}

export function formatGeoipLabel(status) {
  if (!status) return t("Unavailable");
  if (!status.present) return t("Not present");
  if (status.mtime_ms == null) return status.file_name || "Present";
  const date = new Date(status.mtime_ms);
  if (Number.isNaN(date.getTime())) return status.file_name || "Present";
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
