import {
  fallbackPayload,
  fallbackSettingsSnapshot,
  fallbackCoreStatus,
  state,
  navInitials,
  primaryNavIds,
  MAX_LOG_ROWS,
  MAX_CONNECTION_ROWS,
  runtime,
} from "./state.js";

export const tauriApi = () => window.__TAURI__;
export const sleep = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

export const invoke = async (command, args = {}) => {
  const api = tauriApi();
  if (!api?.core?.invoke) {
    if (command === "boot_payload") return fallbackPayload;
    if (command === "quit_app") return null;
    if (command === "force_quit_app") return null;
    if (command === "current_platform_design") return fallbackPayload.platform;
    if (command === "provision_core_binary") {
      return {
        installed: false,
        source_path: null,
        target_path: fallbackCoreStatus.spec.binary_path,
        message: "Bundled core provisioning is unavailable outside Tauri",
      };
    }
    if (command === "install_core_from_url" || command === "install_latest_mihomo_core" || command === "install_pinned_mihomo_core") {
      throw new Error("Core installer is unavailable outside the Tauri runtime");
    }
    if (command === "system_proxy_state") return state.toggles.systemProxy ? "Enabled" : "Disabled";
    if (command === "network_diagnostics") return null;
    if (command === "read_settings_snapshot") return fallbackSettingsSnapshot;
    if (command === "write_settings_snapshot") return { ...fallbackSettingsSnapshot, persisted: true, settings: args.settings };
    if (command === "reset_settings_snapshot") return fallbackSettingsSnapshot;
    if (command === "set_system_proxy_enabled") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, system_proxy: args.enabled } };
    }
    if (command === "set_tun_enabled") {
      if (args.enabled) throw new Error("TUN runtime is unavailable in browser preview");
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, tun_mode: args.enabled } };
    }
    if (command === "run_tray_script") return { status: 0, stdout: "preview tray script", stderr: "" };
    if (command === "run_child_process") return { status: 0, stdout: "preview child process", stderr: "" };
    if (command === "toggle_devtools") return null;
    if (command === "move_dashboard_to_nearest_monitor") return null;
    if (command === "set_mixin_enabled") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, mixin: args.enabled } };
    }
    if (command === "set_launch_at_login_enabled") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, launch_at_login: args.enabled } };
    }
    if (command === "install_helper_service") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, service_mode: "installed" } };
    }
    if (command === "uninstall_helper_service") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, service_mode: "not-installed" } };
    }
    if (command === "controller_snapshot") return null;
    if (command === "providers_snapshot") return null;
    if (command === "rules_snapshot") return null;
    if (command === "update_proxy_provider") return null;
    if (command === "update_rule_provider") return null;
    if (command === "health_check_proxy_provider") return null;
    if (command === "update_all_proxy_providers") return emptyProviderBatch("update-proxy");
    if (command === "update_all_rule_providers") return emptyProviderBatch("update-rule");
    if (command === "health_check_all_proxy_providers") return emptyProviderBatch("health-check-proxy");
    if (command === "service_mode_status") return "Unknown";
    if (command === "controller_version") return { version: "preview", meta: true };
    if (command === "read_runtime_config_text") return "mixed-port: 7890\n";
    if (command === "dns_query") return { Status: 0, Answer: [] };
    if (command === "set_bind_address") return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, "bind-address": args.address } };
    if (command === "open_login_items_settings") return null;
    if (command === "apply_restore_dns_servers") return "updated DNS on 0/0 service(s)";
    if (command === "check_for_updates") {
      return { available: false, current: "0.2.0" };
    }
    if (command === "install_available_update") {
      return { installed: false, reason: "preview" };
    }
    if (command === "disable_service_mode") return null;

    if (command === "enable_service_mode") return "RequiresApproval";
    if (command === "disable_service_mode") return null;
    if (command === "geoip_database_status") {
      return {
        present: false,
        file_name: "geoip.metadb",
        path: `${fallbackSettingsSnapshot.paths.app_home}/geoip.metadb`,
        mtime_ms: null,
        size_bytes: null,
      };
    }
    if (command === "update_geoip_database") {
      const now = Date.now();
      return {
        status: {
          present: true,
          file_name: "geoip.metadb",
          path: `${fallbackSettingsSnapshot.paths.app_home}/geoip.metadb`,
          mtime_ms: now,
          size_bytes: 1024,
        },
        source_url: "https://example.invalid/geoip.metadb",
        bytes: 1024,
      };
    }
    if (command === "refresh_tray_menu") return null;
    if (command === "start_connections_stream") return null;
    if (command === "start_log_stream") return null;
    if (command === "parse_deep_links") {
      return (args.urls ?? []).map((url) => ({ raw: url, intent: null, error: "parse_deep_links is unavailable outside Tauri" }));
    }
    if (command === "import_profile_url") {
      const id = `import-${Date.now()}`;
      return { id, name: args.name ?? "Imported Profile", path: `${fallbackSettingsSnapshot.paths.profiles_dir}/${id}.yaml`, bytes: 0, activated: args.activate };
    }
    if (command === "import_profile_text") {
      const id = `local-${Date.now()}`;
      return { id, name: args.name ?? "Local Profile", path: `${fallbackSettingsSnapshot.paths.profiles_dir}/${id}.yaml`, bytes: args.body?.length ?? 0, activated: args.activate };
    }
    if (command === "update_profile") throw new Error("Profile update is unavailable outside the Tauri runtime");
    if (command === "read_profile_text") {
      return {
        id: args.id,
        name: args.id,
        path: `${fallbackSettingsSnapshot.paths.profiles_dir}/${args.id}.yaml`,
        body: "proxies: []\nproxy-groups: []\nrules: []\n",
        generated_body: "mixed-port: 7890\nproxies: []\nproxy-groups: []\nrules: []\n",
        active: false,
        source_url: null,
      };
    }
    if (command === "save_profile_text") return { id: args.id, path: "", bytes: args.body?.length ?? 0, active: false };
    if (command === "profile_qrcode_svg") throw new Error("Profile QRCode is unavailable outside the Tauri runtime");
    if (command === "profiles_snapshot") return [];
    if (command === "delete_profile") return true;
    if (command === "reveal_profile") return null;
    if (command === "open_profile_externally") return null;
    if (command === "open_external_url") return null;
    if (command === "update_profile_info") return null;
    if (command === "reveal_home_directory") return null;
    if (command === "reveal_logs_directory") return null;
    if (command === "apply_active_profile") throw new Error("Profile apply is unavailable outside the Tauri runtime");
    if (command === "set_proxy_mode") return null;
    if (command === "set_allow_lan") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, allow_lan: args.enabled } };
    }
    if (command === "set_ipv6") {
      return { ...fallbackSettingsSnapshot, persisted: true, settings: { ...fallbackSettingsSnapshot.settings, enable_ipv6: args.enabled } };
    }
    if (command === "set_log_level") return null;
    if (command === "select_proxy") return null;
    if (command === "test_proxy_delays") return [];
    if (command === "close_connection") return null;
    if (command === "close_all_connections") return null;
    if (command === "flush_fake_ip_cache") return null;
    if (command === "core_status") return fallbackCoreStatus;
    if (command === "start_core") return fallbackCoreStatus;
    if (command === "stop_core") return { ...fallbackCoreStatus, state: "Stopped", message: "Core stopped" };
    return null;
  }
  return api.core.invoke(command, args);
};

export const listen = async (event, handler) => {
  const api = tauriApi();
  if (!api?.event?.listen) return () => {};
  return api.event.listen(event, handler);
};

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function formatRuntime(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds) || 0));
  const hours = Math.floor(total / 3600).toString().padStart(2, "0");
  const minutes = Math.floor((total % 3600) / 60).toString().padStart(2, "0");
  const secs = Math.floor(total % 60).toString().padStart(2, "0");
  return `${hours} : ${minutes} : ${secs}`;
}

// Map the real SMAppService status (service_mode_status command) to a label.
export function serviceModeLabel(status) {
  switch (status) {
    case "Enabled":
      return "Enabled";
    case "RequiresApproval":
      return "Needs Approval";
    case "NotRegistered":
    case "NotFound":
      return "Not Installed";
    default:
      return "Unknown";
  }
}

export function serviceModeNeedsAttention(status) {
  return status !== "Enabled";
}

export function tunModeValueLabel(tunEnabled, serviceStatus) {
  if (tunEnabled) return "On";
  if (serviceStatus === "Enabled") return "Off";
  return "Service Mode required";
}

export function formatGeoipLabel(status, updating) {
  if (updating) return "Updating…";
  if (!status) return "Loading…";
  if (!status.present) return "Missing";
  if (status.mtime_ms == null) return status.file_name || "Present";
  const date = new Date(status.mtime_ms);
  if (Number.isNaN(date.getTime())) return status.file_name || "Present";
  const pad = (n) => String(n).padStart(2, "0");
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

export function pageById(id) {
  return state.payload.pages.find((page) => page.id === id) ?? state.payload.pages[0];
}

export function activeProfile() {
  return state.profiles.find((profile) => profile.active)
    ?? state.profiles[0]
    ?? { id: "none", name: "No Profile", type: "Local", updated: "never", rules: 0, traffic: "0 B", active: false };
}
