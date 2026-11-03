// Shared fixtures of the settings and engine tests: a settings snapshot
// builder, log readers, and the hook that resets the fake host and the shared
// state before every test of each file that imports this module.
import { clipboard, dom, host } from "./fake-host.mjs";
import { stopEngine } from "./engine.mjs";
import { beforeEach } from "node:test";
import { state, runtime } from "../../src/state.js";

const lastLog = () => state.logs[0];
const messages = () => state.logs.map((entry) => entry.message);

const SETTINGS = Object.freeze({
  check_for_updates: true, font_family: "", language: "system", launch_at_login: false,
  retain_window_bounds: true, silent_start: false, theme: "system",
});
const snapshotOf = (settings = {}, loginItem = {}) => ({
  persisted: true,
  resolved_locale: "en",
  settings: { ...SETTINGS, ...settings },
  launch_at_login: { persisted_intent: false, live_status: "not_registered", matches_persisted_intent: true, ...loginItem },
});

beforeEach(() => {
  host.reset();
  dom.reset();
  clipboard.written.length = 0;
  clipboard.writeError = null;
  state.logs = [];
  state.payload = { product: { name: "Clash for Mac", version: "0.5.1", operating_system: "macos", architecture: "arm64" }, native_ui: {} };
  state.glassDialog = null;
  state.projection = { mixedPort: 7890, error: null };
  state.settingsUnavailableReason = null;
  state.engineMutationBusy = false;
  state.engineMutationError = null;
  state.migrationHandoff = false;
  state.activePage = "general";
  runtime.startupRecovery.delays = [];
  stopEngine();
});

export {
  SETTINGS, lastLog, messages, snapshotOf,
};
