// The connection and request-log streams of the running engine. Start and
// stop requests are serialised per stream and bound to the engine identity.
import { state, runtime } from "./state.js";
import { errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { captureEngineIdentityToken, engineIdentityTokenIsCurrent, normalizeStreamBinding } from "./engine-identity.js";

function queueLiveStreamChange(lane, running, commands) {
  lane.desiredRunning = running;
  lane.intentEpoch += 1;
  const intentEpoch = lane.intentEpoch;
  const operation = lane.operation.then(async () => {
    if (intentEpoch !== lane.intentEpoch) return false;
    if (!running) {
      const token = captureEngineIdentityToken();
      const expected = lane.binding;
      lane.binding = null;
      if (expected) await commands.stop(expected);
      return intentEpoch === lane.intentEpoch
        && (expected === null || engineIdentityTokenIsCurrent(token));
    }

    const token = captureEngineIdentityToken();
    if (!engineIdentityTokenIsCurrent(token)) return false;
    const response = await commands.start();
    const binding = normalizeStreamBinding(response, commands.stream, token.runtimeIdentity);
    if (intentEpoch !== lane.intentEpoch || !engineIdentityTokenIsCurrent(token)) {
      if (!lane.desiredRunning) await commands.stop(binding);
      return false;
    }
    lane.binding = binding;
    return true;
  });
  lane.operation = operation.catch(() => {});
  return operation;
}

export function setConnectionsStreamRunning(running) {
  return queueLiveStreamChange(runtime.connectionsLiveStream, running, {
    stream: "connections",
    start: () => invoke("start_connections_stream"),
    stop: (expected) => invoke("stop_connections_stream", { expected }),
  });
}

export function setLogStreamRunning(running) {
  return queueLiveStreamChange(runtime.logLiveStream, running, {
    stream: "request-logs",
    start: () => invoke("start_log_stream"),
    stop: (expected) => invoke("stop_log_stream", { expected }),
  });
}

export async function startLiveStreams() {
  const engineEpoch = runtime.engineIdentityEpoch;
  const running = Boolean(state.engine.active);
  const streams = [
    ["connections", () => setConnectionsStreamRunning(running && !state.connectionPaused)],
    ["logs", () => setLogStreamRunning(running && !state.logsPaused)],
  ];
  for (const [name, apply] of streams) {
    if (engineEpoch !== runtime.engineIdentityEpoch) return;
    try {
      await apply();
      if (engineEpoch !== runtime.engineIdentityEpoch) return;
    } catch (error) {
      if (engineEpoch !== runtime.engineIdentityEpoch) return;
      appendLog("error", name, t("Live stream unavailable: {error}", { error: errorText(error) }));
    }
  }
}
