import { initialState, MAX_LOG_ROWS } from "./state.js";
import { redactDiagnosticText } from "./format.js";

let state = initialState();
const subscribers = new Set();

function notify() {
  for (const subscriber of subscribers) subscriber(state);
}

export const store = Object.freeze({
  get() {
    return state;
  },

  update(patch) {
    state = { ...state, ...patch };
    notify();
    return state;
  },

  updateEngine(patch) {
    state = { ...state, engine: { ...state.engine, ...patch } };
    notify();
    return state.engine;
  },

  addLog(entry) {
    const normalized = {
      at: (entry.at instanceof Date ? entry.at.toISOString() : String(entry.at ?? new Date().toISOString())).slice(0, 64),
      level: ["debug", "info", "warning", "error"].includes(entry.level) ? entry.level : "info",
      source: String(entry.source ?? "application").slice(0, 64),
      message: redactDiagnosticText(entry.message ?? "").slice(0, 4096),
    };
    state = { ...state, logs: [...state.logs, normalized].slice(-MAX_LOG_ROWS) };
    notify();
  },

  clearLogs() {
    state = { ...state, logs: [] };
    notify();
  },

  subscribe(subscriber) {
    subscribers.add(subscriber);
    return () => subscribers.delete(subscriber);
  },
});
