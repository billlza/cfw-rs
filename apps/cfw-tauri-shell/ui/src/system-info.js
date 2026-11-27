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

// The network settings as the host observes them. The host makes one
// observation at a time, and the page asks for none while one is under way: a
// read asked for then is answered by the next observation, which begins as the
// one under way ends and answers every read asked for until it begins. Each
// read is so answered by an observation that began after it was asked for, as
// a read after a change of the network needs, and the observations end in the
// order they began. One that ran out of time runs on in the host, which lets
// the next wait for it there. Settings shows what the one that ended last
// found, and says that the network settings could not be read when it failed,
// whoever asked for it.
let observing = null;
let waiting = null;

async function observation() {
  try {
    const diagnostics = await invoke("network_diagnostics");
    networkDiagnosticsView(diagnostics, serviceProxyLabel);
    state.networkDiagnostics = diagnostics;
    return diagnostics;
  } catch (error) {
    state.networkDiagnostics = null;
    throw error;
  }
}

function observe() {
  const observed = observation();
  observing = observed;
  const ended = () => {
    observing = null;
    const reads = waiting;
    waiting = null;
    if (reads !== null) observe().then(reads.resolve, reads.reject);
  };
  observed.then(ended, ended);
  return observed;
}

/// An observation of the network settings for a dialog that shows it. Its
/// failure is the dialog's to say.
export function readNetworkDiagnostics() {
  if (observing === null) return observe();
  if (waiting === null) {
    const reads = {};
    reads.promise = new Promise((resolve, reject) => { reads.resolve = resolve; reads.reject = reject; });
    waiting = reads;
  }
  return waiting.promise;
}

/// An observation of the network settings for the pages, which says whether
/// it read them. Its failure is logged.
export async function loadNetworkDiagnostics() {
  try {
    await readNetworkDiagnostics();
    return true;
  } catch (error) {
    appendLog("error", "network", t("Unable to inspect network settings: {error}", { error: errorText(error) }));
    return false;
  }
}
