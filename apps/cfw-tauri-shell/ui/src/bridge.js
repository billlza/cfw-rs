const COMMANDS = new Set([
  "boot_payload",
  "read_settings_snapshot",
  "write_settings_snapshot",
  "set_launch_at_login_enabled",
  "engine_snapshot",
  "set_engine_mode",
  "legacy_retirement_status",
  "prepare_legacy_cutover",
  "disable_service_mode",
  "profiles_snapshot",
  "import_profile_text",
  "profile_credential_requirements",
  "profile_credential_presence",
  "provision_profile_credentials",
  "preview_credential_gc",
  "commit_credential_gc",
  "cancel_credential_gc",
  "select_profile",
  "delete_profile",
  "check_for_updates",
  "install_available_update",
  "cancel_update_install",
  "quit_app",
]);

const EVENTS = new Set([
  "cfw://page",
  "cfw://settings-changed",
  "cfw://update-available",
  "cfw://update-progress",
  "cfw://engine-snapshot",
  "cfw://engine-event",
]);

export class BridgeError extends Error {
  constructor(operation, message, cause = null) {
    super(`${operation}: ${message}`, cause ? { cause } : undefined);
    this.name = "BridgeError";
    this.operation = operation;
  }
}

export async function invoke(command, args = {}) {
  if (!COMMANDS.has(command)) {
    throw new BridgeError(command, "command is not permitted by the renderer allowlist");
  }
  try {
    return await tauriInvoke(command, args);
  } catch (error) {
    if (error instanceof BridgeError) throw error;
    const detail = error instanceof Error ? error.message : String(error);
    throw new BridgeError(command, detail, error);
  }
}

export async function listen(eventName, handler) {
  if (!EVENTS.has(eventName)) {
    throw new BridgeError(eventName, "event is not permitted by the renderer allowlist");
  }
  try {
    return await tauriListen(eventName, handler);
  } catch (error) {
    if (error instanceof BridgeError) throw error;
    const detail = error instanceof Error ? error.message : String(error);
    throw new BridgeError(eventName, detail, error);
  }
}
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";
