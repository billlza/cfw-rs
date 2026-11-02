// The selected profile projected into the engine configuration, read so the
// dashboard shows the real inbound and controller endpoint.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";

export function createRuntimeProjection({ runtimeSettingsUI }) {
  /// Runtime projection is an offline operation owned by the selected profile,
  /// not by the loopback controller. Repository failure and an actually empty
  /// selection remain distinct fail-closed reasons.
  function runtimeProjectionActionAllowed(action, source = "profile") {
    if (state.profilesUnavailableReason) {
      appendLog("error", source, t("{action} is unavailable because the profile repository could not be read: {profilesUnavailableReason}", { action: action, profilesUnavailableReason: state.profilesUnavailableReason }));
      return false;
    }
    const invalid = selectedInvalidProfile();
    if (invalid) {
      appendLog("error", source, t("{action} is unavailable: the selected profile “{name}” is invalid: {error}", { action: action, name: invalid.name, error: invalid.error }));
      return false;
    }
    if (!state.profiles.some((profile) => profile.active === true)) {
      appendLog("info", source, t("{action} requires a selected profile", { action: action }));
      return false;
    }
    return true;
  }

  /// The selected stored profile when it fails validation.
  function selectedInvalidProfile() {
    return state.invalidProfiles.find((profile) => profile.selected);
  }

  /// Reads the projected engine configuration so the dashboard can show the real
  /// inbound and controller endpoint instead of a remembered preference. Without a
  /// selected profile there is no projection, which is reported, not invented.
  async function loadRuntimeProjection() {
    // Effective DNS may change with the selected profile even when the saved
    // user preferences have not changed.
    await runtimeSettingsUI.load();
    if (state.profilesUnavailableReason) {
      state.projection = {
        mixedPort: null,
        listenAddress: null,
        controller: null,
        logLevel: null,
        error: t("profile state is unavailable: {profilesUnavailableReason}", { profilesUnavailableReason: state.profilesUnavailableReason }),
      };
      return false;
    }
    const invalid = selectedInvalidProfile();
    if (invalid) {
      state.projection = {
        mixedPort: null,
        listenAddress: null,
        controller: null,
        logLevel: null,
        error: t("the selected profile “{name}” is invalid: {error}", { name: invalid.name, error: invalid.error }),
      };
      return false;
    }
    if (!state.profiles.some((profile) => profile.active === true)) {
      state.projection = {
        mixedPort: null,
        listenAddress: null,
        controller: null,
        logLevel: null,
        error: "no active profile is selected",
      };
      return false;
    }
    try {
      const document = JSON.parse(await invoke("read_runtime_config_text"));
      const inbound = (document.inbounds ?? []).find((entry) => entry?.type === "mixed" && entry?.tag === "cfw-system-proxy");
      state.projection = {
        mixedPort: Number.isInteger(inbound?.listen_port) ? inbound.listen_port : null,
        listenAddress: typeof inbound?.listen === "string" ? inbound.listen : null,
        controller: document.experimental?.clash_api?.external_controller ?? null,
        logLevel: document.log?.disabled === true ? "silent" : document.log?.level ?? null,
        error: null,
      };
      return true;
    } catch (error) {
      state.projection = {
        mixedPort: null,
        listenAddress: null,
        controller: null,
        logLevel: null,
        error: errorText(error),
      };
      appendLog("error", "profile", t("Active profile projection could not be read: {error}", { error: state.projection.error }));
      return false;
    }
  }

  return { runtimeProjectionActionAllowed, loadRuntimeProjection };
}
