// The page's own reads of the runtime network settings, answered or refused by
// the stand-in host: for tests of what a page shows with, without and after a
// failed read. Nothing here writes the dashboard state the page derives.
import assert from "node:assert/strict";
import { emit, rejected, responses, state } from "./render-harness.mjs";

const LAN = Object.freeze({ listen: "0.0.0.0", port: 7898, allowed_source_cidrs: Object.freeze(["192.168.1.0/24"]) });
/// Where each stored switch rests. The host stores a switch only while it is
/// away from there, and always reports the value in effect.
const RESTING = Object.freeze({ mainland_china_direct: false, dns_leak_protection: false, webrtc_leak_protection: false, tcp_concurrency: true });

/// The page reads the settings again, as it does after every event of the
/// host. The host answers with `original` changed to LAN sharing and IPv6 DNS
/// as asked and to the given values of the stored switches. A switch that is
/// not given is where it rests, whatever `original` stores for it.
export async function readRuntimeSettings(original, { allowLan = false, ipv6Dns = true, ...switches } = {}) {
  for (const field of Object.keys(switches)) assert.ok(field in RESTING, `${field} is no stored switch`);
  const lan = allowLan ? LAN : null;
  const values = { ...RESTING, ...switches };
  const stored = Object.fromEntries(Object.entries(values).filter(([field, value]) => value !== RESTING[field]));
  const others = Object.fromEntries(Object.entries(original.settings).filter(([field]) => !(field in RESTING)));
  responses.read_runtime_settings_snapshot = {
    ...original, saved_ipv6_dns_enabled: ipv6Dns,
    settings: { ...others, ipv6_dns_enabled: ipv6Dns, allow_lan: allowLan, lan_proxy: lan, ...stored },
    effective: { ...original.effective, ipv6_dns_enabled: ipv6Dns, lan_proxy: lan, ...values },
  };
  await emit("cfw://settings-changed", responses.read_settings_snapshot);
  assert.equal(state.runtimeSettings, responses.read_runtime_settings_snapshot);
  assert.equal(state.runtimeSettingsError, null);
}

/// The same read after something else than the app changed the settings file:
/// the host reports `saved` as the saved settings and says that they are not
/// in force, and what the engine runs with stays as `running` has it.
export async function readRuntimeSettingsNotInForce(running, saved, revision) {
  responses.read_runtime_settings_snapshot = { ...running, settings: saved, revision, in_force: false };
  await emit("cfw://settings-changed", responses.read_settings_snapshot);
  assert.equal(state.runtimeSettings, responses.read_runtime_settings_snapshot);
  assert.equal(state.runtimeSettingsError, null);
}

/// The same read, refused by the host with `message`: the page keeps the
/// settings it had, beside the refusal.
export async function refuseRuntimeSettingsRead(message) {
  const kept = state.runtimeSettings;
  rejected.read_runtime_settings_snapshot = message;
  try {
    await emit("cfw://settings-changed", responses.read_settings_snapshot);
  } finally {
    delete rejected.read_runtime_settings_snapshot;
  }
  assert.equal(state.runtimeSettingsError, message);
  assert.equal(state.runtimeSettings, kept);
}
