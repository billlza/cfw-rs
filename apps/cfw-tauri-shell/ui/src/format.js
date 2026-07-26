import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";

import { MAX_LOG_ROWS, PAGES, state } from "./state.js";

/// Every command this dashboard is allowed to invoke. The list exists so a typo
/// or a resurrected retired command fails in the renderer instead of reaching
/// the IPC boundary, and so `ui/tests/contract.test.mjs` can prove the whole
/// surface against `generate_handler!` mechanically.
export const UI_COMMANDS = Object.freeze([
  "apply_active_profile",
  "boot_payload",
  "cancel_credential_gc",
  "check_for_updates",
  "close_all_connections",
  "close_connection",
  "commit_credential_gc",
  "controller_snapshot",
  "controller_version",
  "current_platform_design",
  "delete_profile",
  "dns_query",
  "engine_snapshot",
  "flush_fake_ip_cache",
  "force_quit_app",
  "geoip_database_status",
  "health_check_all_proxy_providers",
  "health_check_proxy_provider",
  "import_profile_file",
  "import_profile_text",
  "import_profile_url",
  "install_available_update",
  "migrate_legacy_cfw_profiles",
  "network_diagnostics",
  "open_login_items_settings",
  "open_page",
  "open_profile_externally",
  "preview_credential_gc",
  "profile_credential_presence",
  "profile_credential_requirements",
  "profile_qrcode_svg",
  "profiles_snapshot",
  "providers_snapshot",
  "provision_profile_credentials",
  "quit_app",
  "read_profile_text",
  "read_runtime_config_text",
  "read_settings_snapshot",
  "refresh_tray_menu",
  "reset_settings_snapshot",
  "reveal_home_directory",
  "reveal_logs_directory",
  "reveal_profile",
  "rules_snapshot",
  "save_profile_text",
  "select_profile",
  "select_proxy",
  "set_launch_at_login_enabled",
  "set_proxy_mode",
  "set_system_proxy_enabled",
  "set_tun_enabled",
  "start_connections_stream",
  "start_log_stream",
  "test_proxy_delays",
  "update_all_proxy_providers",
  "update_all_rule_providers",
  "update_profile",
  "update_profile_info",
  "update_proxy_provider",
  "update_rule_provider",
  "write_settings_snapshot",
]);

/// Every event this dashboard subscribes to. `tauri://drag-drop` is emitted by
/// the webview itself; the rest are emitted by this application.
export const UI_EVENTS = Object.freeze([
  "cfw://connections-snapshot",
  "cfw://engine-event",
  "cfw://engine-snapshot",
  "cfw://log-lines",
  "cfw://page",
  "cfw://settings-changed",
  "cfw://stream-error",
  "cfw://update-available",
  "cfw://update-progress",
  "tauri://drag-drop",
]);

const COMMANDS = new Set(UI_COMMANDS);
const EVENTS = new Set(UI_EVENTS);

export const sleep = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

export const invoke = async (command, args = {}) => {
  if (!COMMANDS.has(command)) {
    throw new Error(`${command} is not a command this dashboard may invoke`);
  }
  return tauriInvoke(command, args);
};

export const listen = async (event, handler) => {
  if (!EVENTS.has(event)) {
    throw new Error(`${event} is not an event this dashboard may subscribe to`);
  }
  return tauriListen(event, handler);
};

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/// Strips credentials out of any diagnostic before it reaches the log pane, a
/// dialog, or the clipboard.
export function redactDiagnosticText(value) {
  return String(value)
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, "$1[redacted]")
    .replace(/([?&](?:token|key|secret|password|auth|sig|signature|x-amz-[a-z0-9-]+|se|sp|sv)=)[^&\s]+/giu, "$1[redacted]")
    .replace(/\b(token|secret|password|authorization|sig|signature|x-amz-[a-z0-9-]+|se|sp|sv)\s*[:=]\s*[^&\s,;]+/giu, "$1=[redacted]");
}

export function errorText(error) {
  if (error instanceof Error && error.message) return redactDiagnosticText(error.message);
  if (typeof error === "string" && error.trim()) return redactDiagnosticText(error);
  return "An unknown error occurred.";
}

export function formatRuntime(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds) || 0));
  const hours = Math.floor(total / 3600).toString().padStart(2, "0");
  const minutes = Math.floor((total % 3600) / 60).toString().padStart(2, "0");
  const secs = Math.floor(total % 60).toString().padStart(2, "0");
  return `${hours} : ${minutes} : ${secs}`;
}

const ENGINE_STATE_LABELS = Object.freeze({
  off: "Off",
  proxy_starting: "ProxyStarting",
  proxy_active: "ProxyActive",
  proxy_stopping: "ProxyStopping",
  tunnel_installing: "TunnelInstalling",
  awaiting_approval: "AwaitingApproval",
  tunnel_starting: "TunnelStarting",
  tunnel_active: "TunnelActive",
  tunnel_stopping: "TunnelStopping",
  failed: "Failed",
});

const ENGINE_STATE_TEXT = Object.freeze({
  Off: "Off",
  ProxyStarting: "Starting…",
  ProxyActive: "On",
  ProxyStopping: "Stopping…",
  TunnelInstalling: "Installing…",
  AwaitingApproval: "Needs approval",
  TunnelStarting: "Starting…",
  TunnelActive: "On",
  TunnelStopping: "Stopping…",
  Failed: "Failed",
});

function engineMode(value) {
  if (value === "system_proxy") return "system-proxy";
  if (value === "tunnel") return "tunnel";
  if (value === "off") return "off";
  throw new TypeError("engine mode is invalid");
}

function validRuntime(runtime, expectedOwner, generation, digest) {
  return runtime?.ready === true
    && runtime.owner === expectedOwner
    && runtime.context?.generation === generation
    && typeof runtime.config_digest === "string"
    && runtime.config_digest.length > 0
    && runtime.config_digest === digest;
}

/// Normalizes an `engine_snapshot` envelope.
///
/// An active data plane is only reported when the runtime identity in the
/// snapshot agrees with the snapshot's own generation and configuration digest
/// and reports itself ready, so a malformed or stale payload can never make the
/// dashboard claim the network is up.
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
  let reason = typeof value.unavailable_reason === "string" && value.unavailable_reason.trim()
    ? redactDiagnosticText(value.unavailable_reason.trim()).slice(0, 512)
    : null;

  if (stateTag === "proxy_active") {
    if (!validRuntime(snapshot.state.runtime, "proxy_agent", snapshot.generation, configDigest)) {
      throw new TypeError("proxy runtime identity does not match the engine snapshot");
    }
    mode = "system-proxy";
  } else if (stateTag === "tunnel_active") {
    if (!validRuntime(snapshot.state.runtime, "packet_tunnel_system_extension", snapshot.generation, configDigest)) {
      throw new TypeError("tunnel runtime identity does not match the engine snapshot");
    }
    mode = "tunnel";
  } else if (stateTag === "failed" && typeof snapshot.state.error === "string") {
    reason = redactDiagnosticText(snapshot.state.error).slice(0, 512);
  }

  const capabilities = value.capabilities && typeof value.capabilities === "object" ? value.capabilities : {};
  return {
    desiredMode,
    mode,
    state: ENGINE_STATE_LABELS[stateTag],
    active: mode !== "off",
    systemProxyActive: mode === "system-proxy",
    tunnelActive: mode === "tunnel",
    systemProxyAvailable: capabilities.system_proxy === true,
    tunnelAvailable: capabilities.tunnel === true,
    availabilityReason: reason,
    generation: snapshot.generation,
    configDigest,
  };
}

export function engineStateLabel(engine) {
  return ENGINE_STATE_TEXT[engine?.state] ?? "Unknown";
}

/// Value shown next to the TUN switch: the tunnel's own lifecycle when it owns
/// the engine, otherwise the plain off state.
export function tunnelValueLabel(engine) {
  if (!engine) return "Unknown";
  const tunnelStates = ["TunnelInstalling", "AwaitingApproval", "TunnelStarting", "TunnelActive", "TunnelStopping"];
  if (tunnelStates.includes(engine.state)) return ENGINE_STATE_TEXT[engine.state];
  if (engine.state === "Failed" && engine.desiredMode === "tunnel") return "Failed";
  return "Off";
}

export function summarizeEngineEvent(payload) {
  if (!payload || typeof payload !== "object") return "invalid engine event payload";
  const type = typeof payload.type === "string" ? payload.type : "event";
  const message = typeof payload.message === "string" ? payload.message : "engine state changed";
  return redactDiagnosticText(`${type}: ${message}`).slice(0, 2048);
}

export function formatGeoipLabel(status) {
  if (!status) return "Unavailable";
  if (!status.present) return "Not present";
  if (status.mtime_ms == null) return status.file_name || "Present";
  const date = new Date(status.mtime_ms);
  if (Number.isNaN(date.getTime())) return status.file_name || "Present";
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

export function formatRate(mbPerSecond) {
  const kb = mbPerSecond * 1024;
  if (kb < 1024) return `${kb.toFixed(kb < 10 ? 2 : 0)} KB/s`;
  return `${mbPerSecond.toFixed(1)} MB/s`;
}

export function formatRelativeUpdated(epochSecs) {
  if (!Number.isFinite(epochSecs) || epochSecs <= 0) return "unknown";
  const deltaMs = Date.now() - epochSecs * 1000;
  if (deltaMs < 0) return new Date(epochSecs * 1000).toLocaleString();
  const seconds = Math.floor(deltaMs / 1000);
  if (seconds < 45) return "a few seconds";
  if (seconds < 90) return "1 minute";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
  if (seconds < 5400) return "1 hour";
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`;
  return new Date(epochSecs * 1000).toLocaleString();
}

export function emptyProviderBatch(action) {
  return { action, requested: 0, succeeded: [], failed: [] };
}

export function providerActionKey(scope, name) {
  return `${scope}:${name}`;
}

export function providerBatchSummary(label, result) {
  const requested = Number(result?.requested ?? 0);
  const succeeded = result?.succeeded?.length ?? 0;
  const failed = result?.failed?.length ?? 0;
  const failures = (result?.failed ?? []).slice(0, 3).map((item) => `${item.name}: ${item.error}`).join("; ");
  return `${label}: ${succeeded}/${requested} succeeded${failed ? `, ${failed} failed${failures ? ` (${failures})` : ""}` : ""}`;
}

export function providerBatchSucceeded(result) {
  return (result?.failed?.length ?? 0) === 0;
}

export function latestDelay(history = []) {
  const last = history.at(-1);
  return Number.isFinite(last?.delay) ? last.delay : null;
}

export function normalizeLevel(level) {
  const value = String(level ?? "info").toLowerCase();
  if (["warn", "wrn", "warning"].includes(value)) return "warning";
  if (["err", "error", "fatal", "ftl"].includes(value)) return "error";
  if (["debug", "dbg", "trace", "trc"].includes(value)) return "debug";
  return "info";
}

export function safeRegex(value) {
  if (!value) return null;
  try {
    return new RegExp(value, "i");
  } catch (_error) {
    return null;
  }
}

/// Bounds and redacts one log row. Kept pure so the bound and the redaction are
/// testable without a DOM.
export function logEntry(level, source, message, time = null, fields = []) {
  return {
    time: String(time ?? new Date().toTimeString().slice(0, 8)).slice(0, 64),
    level: normalizeLevel(level),
    source: String(source ?? "shell").slice(0, 64),
    message: redactDiagnosticText(message ?? "").slice(0, 4096),
    fields: (Array.isArray(fields) ? fields : []).slice(0, 32).map((field) => ({
      key: String(field?.key ?? "").slice(0, 64),
      value: redactDiagnosticText(String(field?.value ?? "")).slice(0, 512),
    })),
  };
}

export function withLogRow(logs, entry) {
  return [entry, ...logs].slice(0, MAX_LOG_ROWS);
}

export function withLogRows(logs, entries) {
  return [...entries.slice().reverse(), ...logs].slice(0, MAX_LOG_ROWS);
}

export function pageById(id) {
  return PAGES.find((page) => page.id === id) ?? PAGES[0];
}

export function activeProfile() {
  return state.profiles.find((profile) => profile.active)
    ?? state.profiles[0]
    ?? { id: "none", name: "No Profile", updated: "never", traffic: "0 B", active: false };
}
