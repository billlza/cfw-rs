import { t } from "./i18n.js";

const REASONS = {
  timeout: "Timed out", connection_failed: "Connection failed", request_failed: "Request failed",
  http_refused: "The endpoint refused the request", invalid_response: "Invalid response",
  wrong_address_family: "The endpoint returned a different IP family", response_too_large: "Response exceeded the limit",
  unsupported_encoding: "Unsupported response encoding", client_unavailable: "HTTPS client unavailable",
  cancelled: "Cancelled", runtime_changed: "The network configuration changed. Run the check again.",
  engine_transition_in_progress: "Wait for the engine to finish changing mode.",
  diagnostics_busy: "A diagnostic is already running", lookup_cooldown: "Wait before another IP lookup (one per minute).",
  provider_rate_limited: "The IP provider refused further lookups. Try again tomorrow.",
  dns_provider_failed: "The DNS test provider returned an error", no_resolvers_observed: "No resolver was observed; the test is inconclusive.",
  no_udp_candidate: "No public UDP candidate was observed; this does not prove protection.",
  webrtc_failed: "WebRTC could not complete the probe", node_selection_unavailable: "The current node selection could not be verified",
  clock_unavailable: "The system clock is unavailable",
};

export function diagnosticFailure(reason) {
  return Object.hasOwn(REASONS, reason) ? t(REASONS[reason]) : t("The diagnostic could not be completed");
}

export function httpVerdict(status) {
  if (status >= 200 && status < 300) return { tone: "ok", label: t("HTTP reachable") };
  if (status >= 300 && status < 400) return { tone: "neutral", label: t("Redirect returned") };
  if (status === 401) return { tone: "neutral", label: t("Authentication required") };
  if (status === 403) return { tone: "attention", label: t("Access refused or challenged") };
  if (status === 429) return { tone: "attention", label: t("Rate limited") };
  return { tone: "attention", label: t("HTTP error") };
}

// Expand IPv6 for comparisons, so compression/case cannot invent a difference.
export function normalizedIp(value) {
  if (typeof value !== "string") return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/u.test(value)) {
    const parts = value.split(".");
    return parts.every((part) => Number(part) <= 255 && String(Number(part)) === part) ? parts.join(".") : null;
  }
  if (!value.includes(":") || !/^[0-9a-f:]+$/iu.test(value)) return null;
  const parts = value.toLowerCase().split("::");
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  if (![...left, ...right].every((part) => /^[0-9a-f]{1,4}$/u.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if ((parts.length === 1 && missing !== 0) || (parts.length === 2 && missing < 1)) return null;
  return [...left, ...Array(missing).fill("0"), ...right].map((part) => part.padStart(4, "0")).join(":");
}

// Whether WebRTC leak protection refuses this window's STUN: the switch is on,
// the tunnel is active and the routing mode is one the rules cover. An unknown
// routing mode is never read as protection.
export function stunRefused({ protection, tunnelActive, mode }) {
  return protection === true && tunnelActive === true && (mode === "Rule" || mode === "Global");
}

// What a UDP result means under the protection that was in force while it ran:
// no exit is the expected outcome of a refusal, and an exit means a packet
// left outside the tunnel.
export function udpProtectionNote(value) {
  if (value?.refused !== true) return null;
  if (value.status === "observed") return "escaped";
  return value.status === "failed" && (value.reason === "timeout" || value.reason === "no_udp_candidate") ? "expected" : null;
}

export function udpComparison(addresses, report) {
  const references = [report?.ipv4, report?.ipv6].filter((item) => item?.status === "observed").map((item) => normalizedIp(item.value));
  const comparable = addresses.map(normalizedIp).filter((ip) => ip && references.some((ref) => ref && ref.includes(":") === ip.includes(":")));
  if (!comparable.length) return "unconfirmed";
  if (comparable.some((ip) => !references.includes(ip))) return "different";
  return comparable.length === addresses.length ? "matched" : "unconfirmed";
}
