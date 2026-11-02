// The verified engine runtime identity: what a request captured, whether it
// still holds, and whether a stream event belongs to the running engine.
import { state, runtime } from "./state.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";

/// Destructive credential maintenance still requires a complete core stop.
export function engineIsOff() {
  return state.engine.state === "Off" && state.engine.desiredMode === "off";
}

/// Every controller-backed mutation/inspection must use the verified runtime
/// identity, never desired mode. Engine Off is an expected state, so the guard
/// records no warning/error and, most importantly, emits no controller IPC.
export function controllerActionAllowed(action, source = "controller") {
  if (state.engine.active) return true;
  state.controllerStatus = "engine off";
  appendLog("info", source, t("{action} is unavailable while the engine is Off", { action: action }));
  return false;
}

export function captureEngineIdentityToken() {
  if (!state.engine.active) return null;
  return Object.freeze({
    epoch: runtime.engineIdentityEpoch,
    generation: state.engine.generation,
    configDigest: state.engine.configDigest,
    runtimeIdentity: state.engine.runtimeIdentity,
  });
}

function runtimeIdentitiesEqual(left, right) {
  return left !== null
    && right !== null
    && left?.owner === right?.owner
    && left?.ready === true
    && right?.ready === true
    && left?.context?.installation_id === right?.context?.installation_id
    && left?.context?.config_epoch === right?.context?.config_epoch
    && left?.context?.generation === right?.context?.generation
    && left?.config_digest === right?.config_digest;
}

export function engineIdentityTokenIsCurrent(token) {
  return token !== null
    && state.engine.active
    && token.epoch === runtime.engineIdentityEpoch
    && token.generation === state.engine.generation
    && token.configDigest === state.engine.configDigest
    && runtimeIdentitiesEqual(token.runtimeIdentity, state.engine.runtimeIdentity);
}

export function engineRuntimeIdentityChanged(previous, next) {
  return previous.active !== next.active
    || previous.generation !== next.generation
    || previous.configDigest !== next.configDigest
    || previous.mode !== next.mode
    || (previous.active && next.active
      && !runtimeIdentitiesEqual(previous.runtimeIdentity, next.runtimeIdentity));
}

function streamBindingsEqual(left, right) {
  return left !== null
    && right !== null
    && left?.stream === right?.stream
    && left?.stream_id === right?.stream_id
    && runtimeIdentitiesEqual(left?.runtime, right?.runtime);
}

export function normalizeStreamBinding(value, expectedStream, expectedRuntime = state.engine.runtimeIdentity) {
  if (!value
    || typeof value !== "object"
    || value.stream !== expectedStream
    || !Number.isSafeInteger(value.stream_id)
    || value.stream_id < 1
    || !runtimeIdentitiesEqual(value.runtime, expectedRuntime)) {
    throw new TypeError(`${expectedStream} stream binding does not match the active engine runtime`);
  }
  return Object.freeze({
    stream: expectedStream,
    stream_id: value.stream_id,
    runtime: expectedRuntime,
  });
}

function streamBindingIsCurrent(binding, expectedStream) {
  return binding !== null
    && binding?.stream === expectedStream
    && state.engine.active
    && runtimeIdentitiesEqual(binding?.runtime, state.engine.runtimeIdentity);
}

export function validatedStreamEventPayload(envelope, binding, expectedStream) {
  if (!streamBindingIsCurrent(binding, expectedStream)
    || !envelope
    || typeof envelope !== "object"
    || !Object.hasOwn(envelope, "payload")
    || !streamBindingsEqual(envelope.provenance, binding)) {
    return undefined;
  }
  return envelope.payload;
}
