// Reads of how this platform runs the network and of its network settings.
import { state } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { platformStartupDesign } from "./platform-presentation.js";
import { networkDiagnosticsView, serviceProxyLabel } from "./network-diagnostics.js";

export async function loadPlatformDesign() {
  try {
    const platform = await invoke("current_platform_design");
    platformStartupDesign(state.payload.product.operating_system, platform);
    state.platform = platform;
  } catch (error) {
    state.platform = null;
    appendLog("error", "shell", t("Unable to read the platform design: {error}", { error: errorText(error) }));
  }
}

export async function loadNetworkDiagnostics() {
  try {
    const diagnostics = await invoke("network_diagnostics");
    networkDiagnosticsView(diagnostics, serviceProxyLabel);
    state.networkDiagnostics = diagnostics;
  } catch (error) {
    state.networkDiagnostics = null;
    appendLog("error", "network", t("Unable to inspect network settings: {error}", { error: errorText(error) }));
  }
}
