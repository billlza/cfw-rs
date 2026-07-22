import { invoke } from "./bridge.js";
import { redactDiagnosticText } from "./format.js";
import { store } from "./store.js";
import { appendLog } from "./streams.js";

const MODES = new Set(["off", "system-proxy", "tunnel"]);
const STATE_LABELS = Object.freeze({
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

export class EngineTransitionError extends Error {
  constructor(message) {
    super(message);
    this.name = "EngineTransitionError";
  }
}

function normalizedMode(value) {
  if (value === "system_proxy") return "system-proxy";
  if (value === "tunnel") return "tunnel";
  if (value === "off") return "off";
  throw new TypeError("Native engine mode is invalid");
}

function validRuntime(runtime, expectedOwner, generation, digest) {
  return runtime?.ready === true
    && runtime.owner === expectedOwner
    && runtime.context?.generation === generation
    && typeof runtime.config_digest === "string"
    && runtime.config_digest.length > 0
    && runtime.config_digest === digest;
}

export function normalizeEngineEnvelope(value) {
  if (!value || typeof value !== "object" || !value.snapshot || typeof value.snapshot !== "object") {
    throw new TypeError("Native engine snapshot envelope is invalid");
  }
  const snapshot = value.snapshot;
  const stateTag = snapshot.state?.state;
  if (!STATE_LABELS[stateTag]) throw new TypeError("Native engine state is invalid");
  if (!Number.isSafeInteger(snapshot.generation) || snapshot.generation < 0) {
    throw new TypeError("Native engine generation is invalid");
  }
  const configDigest = typeof snapshot.config_digest === "string" ? snapshot.config_digest : null;
  const desiredMode = normalizedMode(snapshot.desired_mode);
  let mode = "off";
  let reason = typeof value.unavailable_reason === "string" && value.unavailable_reason.trim()
    ? redactDiagnosticText(value.unavailable_reason.trim()).slice(0, 512)
    : "The signed native engine bridge has not reported capability.";

  if (stateTag === "proxy_active") {
    if (!validRuntime(snapshot.state.runtime, "proxy_agent", snapshot.generation, configDigest)) {
      throw new TypeError("Proxy runtime identity does not match the engine snapshot");
    }
    mode = "system-proxy";
  } else if (stateTag === "tunnel_active") {
    if (!validRuntime(snapshot.state.runtime, "packet_tunnel_system_extension", snapshot.generation, configDigest)) {
      throw new TypeError("Tunnel runtime identity does not match the engine snapshot");
    }
    mode = "tunnel";
  } else if (stateTag === "failed" && typeof snapshot.state.error === "string") {
    reason = redactDiagnosticText(snapshot.state.error).slice(0, 512);
  }

  const capabilities = value.capabilities && typeof value.capabilities === "object" ? value.capabilities : {};
  const cutoverReason = typeof value.cutover_unavailable_reason === "string"
    ? redactDiagnosticText(value.cutover_unavailable_reason).slice(0, 512)
    : null;
  return {
    desiredMode,
    mode,
    state: STATE_LABELS[stateTag],
    systemProxyActive: mode === "system-proxy",
    tunnelActive: mode === "tunnel",
    systemProxyAvailable: capabilities.system_proxy === true,
    tunnelAvailable: capabilities.tunnel === true,
    cutoverReady: value.cutover_ready === true,
    cutoverReason,
    availabilityReason: reason,
    tunnelReason: reason,
    generation: snapshot.generation,
    configDigest,
  };
}

export function normalizeRetirementStatus(value) {
  if (!value || typeof value !== "object" || typeof value.state !== "string") {
    throw new TypeError("Legacy retirement status is invalid");
  }
  if (value.state === "cleared") return { state: "cleared", action: null, message: "Legacy network service is fully retired." };
  if (value.state === "awaiting_confirmation") {
    return {
      state: "awaiting_confirmation",
      action: null,
      message: "The existing VPN remains untouched. Stage and select a replacement profile; cutover stays blocked until the signed native replacement passes preflight and you explicitly confirm.",
    };
  }
  if (value.state === "cleaning") {
    return {
      state: "cleaning",
      action: null,
      message: "The explicitly confirmed one-way legacy network cutover is running.",
    };
  }
  if (value.state === "post_cutover_cleanup_required" && typeof value.message === "string") {
    return {
      state: value.state,
      action: "retry-data-cleanup",
      message: redactDiagnosticText(value.message).slice(0, 512),
    };
  }
  if (value.state === "recovery_start_required"
    && typeof value.message === "string"
    && ["system_proxy", "tunnel"].includes(value.target)) {
    return {
      state: value.state,
      action: "recover-replacement",
      target: normalizedMode(value.target),
      message: redactDiagnosticText(value.message).slice(0, 512),
    };
  }
  if (value.state === "manual_cleanup_required"
    && (value.action === "retry" || value.action === "review_dns")
    && typeof value.message === "string") {
    return { state: value.state, action: value.action, message: redactDiagnosticText(value.message).slice(0, 512) };
  }
  throw new TypeError("Legacy retirement status is invalid");
}

export async function refreshEngineState() {
  const [engineEnvelope, retirementPayload] = await Promise.all([
    invoke("engine_snapshot"),
    invoke("legacy_retirement_status"),
  ]);
  const engine = normalizeEngineEnvelope(engineEnvelope);
  const legacyRetirement = normalizeRetirementStatus(retirementPayload);
  store.update({ engine, legacyRetirement });
  return engine;
}

export async function setEngineMode(targetMode) {
  if (!MODES.has(targetMode)) throw new EngineTransitionError(`Unsupported engine mode: ${targetMode}`);
  if (store.get().busyAction) throw new EngineTransitionError("Another engine operation is already running");
  store.update({ busyAction: `engine:${targetMode}`, fatalError: null });
  try {
    const before = await refreshEngineState();
    if (store.get().legacyRetirement.state !== "cleared" && targetMode !== "off") {
      throw new EngineTransitionError(store.get().legacyRetirement.message);
    }
    if (targetMode === "system-proxy" && !before.systemProxyAvailable) {
      throw new EngineTransitionError(before.availabilityReason);
    }
    if (targetMode === "tunnel" && !before.tunnelAvailable) {
      throw new EngineTransitionError(before.tunnelReason);
    }
    if (before.mode === targetMode && before.desiredMode === targetMode) return before;

    const nativeMode = targetMode === "system-proxy" ? "system_proxy" : targetMode;
    const envelope = await invoke("set_engine_mode", { mode: nativeMode });
    const after = envelope ? normalizeEngineEnvelope(envelope) : await refreshEngineState();
    if (envelope) store.updateEngine(after);
    if (after.state === "Failed") throw new EngineTransitionError(after.tunnelReason);
    if (targetMode === "off" && after.state !== "Off") {
      throw new EngineTransitionError(`Engine did not reach Off; native state is ${after.state}`);
    }
    appendLog("info", "engine", `Mode request accepted: ${targetMode}`);
    return after;
  } catch (error) {
    try {
      await refreshEngineState();
    } catch (refreshError) {
      const transitionMessage = error instanceof Error ? error.message : String(error);
      const refreshMessage = refreshError instanceof Error ? refreshError.message : String(refreshError);
      throw new EngineTransitionError(`Transition failed (${transitionMessage}); state refresh also failed (${refreshMessage})`);
    }
    throw error;
  } finally {
    store.update({ busyAction: null });
  }
}

function normalizeCutoverPreparation(value) {
  if (!value || typeof value !== "object" || typeof value.status !== "string") {
    throw new TypeError("Native cutover preparation is invalid");
  }
  const target = normalizedMode(value.target);
  if (target === "off") throw new TypeError("Cutover target cannot be Off");
  if (value.status === "awaiting_approval") {
    return Object.freeze({ status: "awaiting-approval", target });
  }
  if (value.status !== "ready"
    || typeof value.receipt_id !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value.receipt_id)
    || typeof value.profile_id !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value.profile_id)
    || !Number.isSafeInteger(value.valid_for_millis)
    || value.valid_for_millis <= 0
    || value.valid_for_millis > 300_000) {
    throw new TypeError("Native cutover receipt is invalid");
  }
  return Object.freeze({
    status: "ready",
    target,
    receiptId: value.receipt_id,
    profileId: value.profile_id,
    validForMillis: value.valid_for_millis,
  });
}

export async function prepareLegacyCutover(targetMode) {
  if (!MODES.has(targetMode) || targetMode === "off") {
    throw new EngineTransitionError(`Unsupported cutover target: ${targetMode}`);
  }
  if (store.get().busyAction) throw new EngineTransitionError("Another engine operation is already running");
  store.update({ busyAction: `cutover-prepare:${targetMode}`, fatalError: null, cutoverPreparation: null });
  try {
    const nativeTarget = targetMode === "system-proxy" ? "system_proxy" : targetMode;
    const preparation = normalizeCutoverPreparation(
      await invoke("prepare_legacy_cutover", { target: nativeTarget }),
    );
    store.update({ cutoverPreparation: preparation });
    await refreshEngineState();
    appendLog(
      "info",
      "migration",
      preparation.status === "ready"
        ? `Replacement ${targetMode} passed cutover preparation`
        : "System Extension approval is pending; approve it, then run Prepare Cutover again",
    );
    return preparation;
  } finally {
    store.update({ busyAction: null });
  }
}

export async function cleanupLegacyService(dnsReviewConfirmed = false) {
  if (store.get().busyAction) throw new EngineTransitionError("Another engine operation is already running");
  const preparation = store.get().cutoverPreparation;
  if (!preparation || preparation.status !== "ready") {
    throw new EngineTransitionError("Run Prepare Cutover before final confirmation");
  }
  store.update({ busyAction: "legacy-cleanup", fatalError: null });
  try {
    // Clear renderer state before invoking the one-shot native authority. The
    // server independently rejects replay even if the renderer is compromised.
    store.update({ cutoverPreparation: null });
    await invoke("disable_service_mode", {
      receiptId: preparation.receiptId,
      cutoverConfirmed: true,
      dnsReviewConfirmed,
    });
    await refreshEngineState();
    if (!["cleared", "post_cutover_cleanup_required"].includes(store.get().legacyRetirement.state)) {
      throw new EngineTransitionError(store.get().legacyRetirement.message);
    }
    if (store.get().engine.mode !== preparation.target) {
      throw new EngineTransitionError("Legacy network was retired but the prepared replacement is not Active");
    }
    appendLog("info", "migration", `Legacy network retired; ${preparation.target} is Active`);
  } catch (error) {
    try {
      await refreshEngineState();
    } catch (refreshError) {
      const detail = refreshError instanceof Error ? refreshError.message : String(refreshError);
      appendLog("warning", "migration", `Cutover state refresh failed: ${redactDiagnosticText(detail)}`);
    }
    throw error;
  } finally {
    store.update({ busyAction: null });
  }
}
