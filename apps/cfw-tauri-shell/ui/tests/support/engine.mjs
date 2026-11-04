// Engine states as the dashboard holds them after normalizing a host status.
import { state, runtime, defaultEngineStatus } from "../../src/state.js";

export const RUNTIME_IDENTITY = Object.freeze({
  owner: "proxy_agent",
  ready: true,
  context: Object.freeze({ installation_id: "installation", config_epoch: 1, generation: 3 }),
  config_digest: "digest",
});

/// A running engine whose runtime identity the dashboard has verified.
export function runEngine(overrides = {}) {
  state.engine = {
    ...defaultEngineStatus,
    state: "Running",
    desiredMode: "system_proxy",
    active: true,
    generation: 3,
    configDigest: "digest",
    runtimeIdentity: RUNTIME_IDENTITY,
    systemProxyActive: true,
    ...overrides,
  };
  return state.engine;
}

/// An engine that is Off by request and by observation.
export function stopEngine(overrides = {}) {
  state.engine = { ...defaultEngineStatus, state: "Off", desiredMode: "off", active: false, ...overrides };
  return state.engine;
}

/// Ends the current engine identity, as a restart or a stop observed meanwhile would.
export function replaceEngineIdentity() {
  runtime.engineIdentityEpoch += 1;
}

/// A stream binding the host returns for a started stream of this engine.
export const streamBinding = (stream, streamId = 1) => ({ stream, stream_id: streamId, runtime: RUNTIME_IDENTITY });
