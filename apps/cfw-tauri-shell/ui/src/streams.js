import { store } from "./store.js";
import { errorMessage, redactDiagnosticText } from "./format.js";

export function appendLog(level, source, message) {
  store.addLog({ level, source, message, at: new Date() });
}

export function logFailure(source, error) {
  appendLog("error", source, errorMessage(error));
}

export function summarizeEngineEvent(payload) {
  if (!payload || typeof payload !== "object") return "Invalid engine event payload";
  const type = typeof payload.type === "string" ? payload.type : "event";
  const message = typeof payload.message === "string" ? payload.message : "Engine state changed";
  return redactDiagnosticText(`${type}: ${message}`).slice(0, 2048);
}
