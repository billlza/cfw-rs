// Proxy delay results: the latest measurement and the reason a probe failed.
import { t } from "./i18n.js";

export function delayFailureLabel(kind) {
  return t({
    timeout: "Timeout",
    not_found: "Not found",
    probe_failed: "Probe failed",
    rejected: "Rejected",
    transport: "Network error",
    invalid_response: "Invalid response",
    invalid_request: "Invalid target",
    unsupported: "Unsupported",
  }[kind] ?? "Probe failed");
}

export function latestDelay(history = []) {
  const last = history.at(-1);
  return Number.isFinite(last?.delay) ? last.delay : null;
}
