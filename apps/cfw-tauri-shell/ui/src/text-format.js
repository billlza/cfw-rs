// Text the dashboard shows: escaping, redaction, sizes, rates and durations.
import { t, formatDate } from "./i18n.js";

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/// Strips credentials out of any diagnostic before it reaches the log pane, a
/// dialog, or the clipboard.
export function redactDiagnosticText(value) {
  return String(value)
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, "$1[redacted]")
    .replace(/([?&](?:token|key|secret|password|auth|sig|signature|x-amz-[a-z0-9-]+|se|sp|sv)=)[^&\s]+/giu, "$1[redacted]")
    .replace(/\b(token|secret|password|authorization|sig|signature|x-amz-[a-z0-9-]+|se|sp|sv)\s*[:=]\s*[^&\s,;]+/giu, "$1=[redacted]");
}

export function errorText(error) {
  if (error instanceof Error && error.message) return redactDiagnosticText(error.message);
  if (typeof error === "string" && error.trim()) return redactDiagnosticText(error);
  return "An unknown error occurred.";
}

export function formatRuntime(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds) || 0));
  const hours = Math.floor(total / 3600).toString().padStart(2, "0");
  const minutes = Math.floor((total % 3600) / 60).toString().padStart(2, "0");
  const secs = Math.floor(total % 60).toString().padStart(2, "0");
  return `${hours} : ${minutes} : ${secs}`;
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

export function formatRate(mbPerSecond) {
  const kb = mbPerSecond * 1024;
  if (kb < 1024) return `${kb.toFixed(kb < 10 ? 2 : 0)} KB/s`;
  return `${mbPerSecond.toFixed(1)} MB/s`;
}

export function formatRelativeUpdated(epochSecs) {
  if (!Number.isFinite(epochSecs) || epochSecs <= 0) return t("unknown");
  const deltaMs = Date.now() - epochSecs * 1000;
  if (deltaMs < 0) return formatDate(new Date(epochSecs * 1000), { dateStyle: "short", timeStyle: "medium" });
  const seconds = Math.floor(deltaMs / 1000);
  if (seconds < 45) return t("a few seconds");
  if (seconds < 90) return t("1 minute");
  if (seconds < 3600) return t("{count} minutes", { count: Math.floor(seconds / 60) });
  if (seconds < 5400) return t("1 hour");
  if (seconds < 86400) return t("{count} hours", { count: Math.floor(seconds / 3600) });
  return formatDate(new Date(epochSecs * 1000), { dateStyle: "short", timeStyle: "medium" });
}

export function safeRegex(value) {
  if (!value) return null;
  try {
    return new RegExp(value, "i");
  } catch (_error) {
    return null;
  }
}
