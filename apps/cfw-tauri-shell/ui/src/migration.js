const CUTOVER_TARGETS = new Set(["system_proxy", "tunnel"]);
const HANDOFF_FAILURE_CODES = new Set([
  "migration_handoff_admission_failed",
  "migration_handoff_failed",
  "migration_handoff_task_failed",
]);
const MAX_RECEIPT_TTL_MILLIS = 5 * 60 * 1000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function exactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === [...expected].sort()[index]);
}

function boundedMessage(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 2048) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function boundedProductField(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 128) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

export function normalizeBootPayload(value) {
  if (!exactKeys(value, [
    "migration_handoff",
    "migration_handoff_renderer_ready",
    "migration_handoff_status",
    "product",
  ])) {
    throw new TypeError("boot payload fields are invalid");
  }
  if (!exactKeys(value.product, ["architecture", "license", "minimum_macos", "name", "version"])) {
    throw new TypeError("boot product fields are invalid");
  }
  if (typeof value.migration_handoff !== "boolean") {
    throw new TypeError("boot migration role is invalid");
  }
  const product = Object.fromEntries(
    Object.entries(value.product).map(([key, field]) => [key, boundedProductField(field, `product ${key}`)]),
  );
  const migrationHandoffStatus = normalizeMigrationHandoffStatus(value.migration_handoff_status);
  const rendererReady = value.migration_handoff_renderer_ready;
  if (!value.migration_handoff) {
    if (rendererReady !== null) {
      throw new TypeError("dashboard boot payload cannot contain renderer readiness authority");
    }
  } else if (rendererReady?.state === "published") {
    if (!exactKeys(rendererReady, ["state"])) {
      throw new TypeError("published renderer readiness fields are invalid");
    }
  } else if (rendererReady?.state === "challenge") {
    if (!exactKeys(rendererReady, ["challenge", "generation", "state"])
      || !Number.isSafeInteger(rendererReady.generation)
      || rendererReady.generation <= 0
      || rendererReady.generation > 0xffff_ffff
      || typeof rendererReady.challenge !== "string"
      || !UUID_V4.test(rendererReady.challenge)) {
      throw new TypeError("renderer readiness challenge is invalid");
    }
  } else {
    throw new TypeError("handoff boot payload requires renderer readiness authority");
  }
  return {
    product,
    migration_handoff: value.migration_handoff,
    migration_handoff_status: migrationHandoffStatus,
    migration_handoff_renderer_ready: rendererReady === null ? null : { ...rendererReady },
  };
}

function target(value) {
  if (!CUTOVER_TARGETS.has(value)) throw new TypeError("cutover target is invalid");
  return value;
}

export function normalizeMigrationHandoffStatus(value) {
  if (value?.state === "idle" || value?.state === "in_progress") {
    if (!exactKeys(value, ["state"])) throw new TypeError("migration handoff status fields are invalid");
    return { state: value.state };
  }
  if (value?.state === "failed") {
    if (!exactKeys(value, ["state", "code", "message"])) {
      throw new TypeError("migration handoff failure fields are invalid");
    }
    if (!HANDOFF_FAILURE_CODES.has(value.code)) {
      throw new TypeError("migration handoff failure code is invalid");
    }
    const message = boundedMessage(value.message, "migration handoff failure");
    if (message.length > 512) throw new TypeError("migration handoff failure is too long");
    return { state: "failed", code: value.code, message };
  }
  throw new TypeError("migration handoff status is invalid");
}

export function normalizeRetirementStatus(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("legacy retirement status is invalid");
  }
  switch (value.state) {
    case "awaiting_confirmation":
    case "cleaning":
    case "cleared":
      if (!exactKeys(value, ["state"])) throw new TypeError("legacy retirement status fields are invalid");
      return { state: value.state };
    case "post_cutover_cleanup_required":
      if (!exactKeys(value, ["state", "message"])) throw new TypeError("post-cutover status fields are invalid");
      return { state: value.state, message: boundedMessage(value.message, "post-cutover message") };
    case "recovery_start_required":
      if (!exactKeys(value, ["state", "target", "message"])) throw new TypeError("recovery status fields are invalid");
      return {
        state: value.state,
        target: target(value.target),
        message: boundedMessage(value.message, "recovery message"),
      };
    case "manual_cleanup_required":
      if (!exactKeys(value, ["state", "action", "message"])) throw new TypeError("manual cleanup status fields are invalid");
      if (!new Set(["retry", "review_dns"]).has(value.action)) {
        throw new TypeError("manual cleanup action is invalid");
      }
      return {
        state: value.state,
        action: value.action,
        message: boundedMessage(value.message, "manual cleanup message"),
      };
    default:
      throw new TypeError("legacy retirement state is unknown");
  }
}

export function unverifiableRetirementStatus(message) {
  return {
    state: "unverifiable",
    message: boundedMessage(message, "retirement verification failure"),
  };
}

export function migrationRoute(retirement, migrationHandoff) {
  switch (retirement?.state) {
    case "cleared":
      return "none";
    case "cleaning":
      return "busy";
    case "unverifiable":
      return "unverifiable";
    case "recovery_start_required":
    case "post_cutover_cleanup_required":
      return migrationHandoff ? "recover" : "launch_recovery";
    case "manual_cleanup_required":
      if (retirement.action === "retry") {
        return migrationHandoff ? "recover" : "launch_recovery";
      }
      if (retirement.action === "review_dns") {
        return migrationHandoff ? "prepare" : "launch_prepare";
      }
      throw new TypeError("manual cleanup route is invalid");
    case "awaiting_confirmation":
      return migrationHandoff ? "prepare" : "launch_prepare";
    default:
      return "unverifiable";
  }
}

export function migrationHandoffRendererAckArguments(
  bootPayload,
  retirement,
  {
    activePage,
    migrationRendered,
    globalActionsBound,
    criticalListenersBound,
  },
) {
  if (!bootPayload.migration_handoff) return null;
  const rendererReady = bootPayload.migration_handoff_renderer_ready;
  if (rendererReady?.state === "published") return null;
  if (retirement?.state === "unverifiable") return null;
  const route = migrationRoute(retirement, true);
  if (!["prepare", "recover"].includes(route)) {
    throw new TypeError("handoff renderer has no actionable migration route");
  }
  if (activePage !== "general"
    || migrationRendered !== true
    || globalActionsBound !== true
    || criticalListenersBound !== true) {
    throw new TypeError("handoff renderer is not ready to acknowledge its first migration view");
  }
  if (rendererReady?.state !== "challenge") {
    throw new TypeError("handoff renderer readiness challenge is unavailable");
  }
  return {
    generation: rendererReady.generation,
    challenge: rendererReady.challenge,
  };
}

export function newCutoverState(targetValue = "system_proxy", message = null) {
  return {
    busy: false,
    target: target(targetValue),
    awaitingApproval: false,
    message,
    receiptId: null,
    receiptTarget: null,
    receiptIssuedAt: null,
    receiptExpiresAt: null,
    confirmedReceiptId: null,
    dnsReviewedReceiptId: null,
  };
}

export function clearCutoverReceipt(cutover, { message = cutover.message, targetValue = cutover.target } = {}) {
  return {
    ...newCutoverState(targetValue ?? "system_proxy", message),
    busy: Boolean(cutover.busy),
  };
}

export function normalizeCutoverPreparation(value, requestedTarget, nowMillis = Date.now()) {
  target(requestedTarget);
  if (!Number.isSafeInteger(nowMillis) || nowMillis < 0) throw new TypeError("receipt clock is invalid");
  if (value?.status === "awaiting_approval") {
    if (!exactKeys(value, ["status", "target"]) || target(value.target) !== requestedTarget) {
      throw new TypeError("awaiting-approval response does not bind the requested target");
    }
    return { status: "awaiting_approval", target: requestedTarget };
  }
  if (value?.status === "ready") {
    if (!exactKeys(value, ["status", "receipt_id", "target", "profile_id", "valid_for_millis"])) {
      throw new TypeError("ready response fields are invalid");
    }
    if (!UUID.test(value.receipt_id) || !UUID.test(value.profile_id) || target(value.target) !== requestedTarget) {
      throw new TypeError("ready response identity is invalid");
    }
    if (!Number.isSafeInteger(value.valid_for_millis)
      || value.valid_for_millis <= 0
      || value.valid_for_millis > MAX_RECEIPT_TTL_MILLIS) {
      throw new TypeError("ready response TTL is invalid");
    }
    const expiresAt = nowMillis + value.valid_for_millis;
    if (!Number.isSafeInteger(expiresAt)) throw new TypeError("ready response expiry overflowed");
    return {
      status: "ready",
      receiptId: value.receipt_id,
      profileId: value.profile_id,
      target: requestedTarget,
      issuedAt: nowMillis,
      expiresAt,
    };
  }
  throw new TypeError("cutover preparation returned an unknown status");
}

export function cutoverReceiptIsCurrent(cutover, nowMillis = Date.now()) {
  return typeof cutover?.receiptId === "string"
    && UUID.test(cutover.receiptId)
    && CUTOVER_TARGETS.has(cutover.receiptTarget)
    && cutover.receiptTarget === cutover.target
    && Number.isSafeInteger(cutover.receiptIssuedAt)
    && Number.isSafeInteger(cutover.receiptExpiresAt)
    && cutover.receiptIssuedAt <= nowMillis
    && nowMillis < cutover.receiptExpiresAt;
}

export function cutoverConfirmArguments(cutover, nowMillis = Date.now()) {
  if (!cutoverReceiptIsCurrent(cutover, nowMillis)) {
    throw new TypeError("Cutover receipt is missing or expired; run Prepare again.");
  }
  if (cutover.confirmedReceiptId !== cutover.receiptId) {
    throw new TypeError("Tick the one-way cutover confirmation for this preparation.");
  }
  return {
    receiptId: cutover.receiptId,
    cutoverConfirmed: true,
    dnsReviewConfirmed: cutover.dnsReviewedReceiptId === cutover.receiptId,
  };
}
