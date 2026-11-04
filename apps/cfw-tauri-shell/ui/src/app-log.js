// The session log every part of the dashboard writes to: bounded, redacted
// rows kept per level.
import { MAX_LOG_ROWS, state } from "./state.js";
import { redactDiagnosticText } from "./text-format.js";

export function appendLog(level, source, message) {
  state.logs = withLogRow(state.logs, logEntry(level, source, message));
}

export function appendLogLines(lines) {
  const normalized = (Array.isArray(lines) ? lines : []).map((line) => logEntry(
    line.level,
    line.source ?? "engine",
    line.message ?? "",
    line.time ?? "live",
    line.fields,
  ));
  state.logs = withLogRows(state.logs, normalized);
}

export function normalizeLevel(level) {
  const value = String(level ?? "info").toLowerCase();
  if (["warn", "wrn", "warning"].includes(value)) return "warning";
  if (["err", "error", "fatal", "ftl"].includes(value)) return "error";
  if (["debug", "dbg", "trace", "trc"].includes(value)) return "debug";
  return "info";
}

/// Bounds and redacts one log row. Kept pure so the bound and the redaction are
/// testable without a DOM.
export function logEntry(level, source, message, time = null, fields = []) {
  const reportedTime = time === "live" ? null : time;
  return {
    time: String(reportedTime ?? new Date().toTimeString().slice(0, 8)).slice(0, 64),
    level: normalizeLevel(level),
    source: String(source ?? "shell").slice(0, 64),
    message: redactDiagnosticText(message ?? "").slice(0, 4096),
    fields: (Array.isArray(fields) ? fields : []).slice(0, 32).map((field) => ({
      key: String(field?.key ?? "").slice(0, 64),
      value: redactDiagnosticText(String(field?.value ?? "")).slice(0, 512),
    })),
  };
}

export function withLogRow(logs, entry) {
  return withLogRows(logs, [entry]);
}

export function withLogRows(logs, entries) {
  // Keep the latest rows independently for each normalized level. A burst of
  // routine traffic must not erase the errors needed to diagnose an outage.
  const counts = new Map();
  const retained = [];
  const retain = (entry) => {
    const level = normalizeLevel(entry.level);
    const count = counts.get(level) ?? 0;
    if (count < MAX_LOG_ROWS) {
      retained.push(entry);
      counts.set(level, count + 1);
    }
  };
  for (let index = entries.length - 1; index >= 0; index -= 1) retain(entries[index]);
  for (const entry of logs) retain(entry);
  return retained;
}
