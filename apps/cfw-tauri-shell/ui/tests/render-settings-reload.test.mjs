// Reload From Disk of the Settings page. The page shows two stores, the
// preferences and the runtime network settings, and the button reads both
// again, each for itself.
import assert from "node:assert/strict";
import test from "node:test";
import {
  appModule, emit, invocationDetails, page, rejected, renderPage, responses, state,
} from "./support/render-harness.mjs";
import { readRuntimeSettings, refuseRuntimeSettingsRead } from "./support/runtime-settings-reads.mjs";

const turns = async () => { for (let turn = 0; turn < 8; turn += 1) await new Promise((resolve) => setImmediate(resolve)); };
/// The host's answers to `command` wait until the test gives them. `asked`
/// has them in the order the page asked.
function hold(command) {
  const answer = responses[command], asked = [];
  responses[command] = () => new Promise((resolve, reject) => {
    asked.push({ answer: () => resolve(answer), refuse: (message) => reject(new Error(message)) });
  });
  return { asked, release() { responses[command] = answer; } };
}
/// The DNS leak protection switch as the page shows it now. The page is not
/// drawn again for this.
const shownSwitch = () => page.innerHTML.match(/<input type="checkbox" data-toggle="dnsLeakProtection"([^>]*)\/>/u)[1];
/// What the log says of failed reads of the network settings, newest first.
const failures = () => state.logs.map((entry) => entry.message).filter((message) => message.startsWith("Network settings failed"));
const reloaded = () => state.logs.filter((entry) => entry.message === "Preferences reloaded from disk").length;

test("Reload From Disk asks for the two stores of the page and for nothing else", async () => {
  // The projected endpoint is not among them. Its answers are taken in the
  // order they arrive, so a reload that is answered late would put an older
  // port back over the one a change has shown since.
  await renderPage("settings");
  const projection = state.projection;
  invocationDetails.length = 0;
  await appModule.handleAction("reload-settings");
  assert.deepEqual(invocationDetails.map((entry) => entry.command).toSorted(), ["read_runtime_settings_snapshot", "read_settings_snapshot"]);
  assert.equal(state.projection, projection);
});

test("Reload From Disk draws what each read came to without waiting for the other", async () => {
  const original = responses.read_runtime_settings_snapshot;
  const refused = "settings store is locked";
  let preferences, network;
  try {
    await readRuntimeSettings(original, { dns_leak_protection: true });
    await renderPage("settings");
    assert.match(shownSwitch(), /checked/u);
    assert.doesNotMatch(shownSwitch(), /disabled/u);
    // The preferences are read with the live state of the login item, which
    // can take its time. The network settings are refused meanwhile, and the
    // page holds their controls at once.
    preferences = hold("read_settings_snapshot");
    rejected.read_runtime_settings_snapshot = refused;
    const first = appModule.handleAction("reload-settings");
    await turns();
    delete rejected.read_runtime_settings_snapshot;
    assert.equal(preferences.asked.length, 1);
    assert.match(shownSwitch(), /disabled/u);
    assert.ok(shownSwitch().includes(`title="${refused}"`));
    assert.deepEqual(failures().slice(0, 1), [`Network settings failed: ${refused}`]);
    // Asked again and answered, they are free at once as well.
    const second = appModule.handleAction("reload-settings");
    await turns();
    assert.equal(preferences.asked.length, 2);
    assert.doesNotMatch(shownSwitch(), /disabled|title=/u);
    assert.match(shownSwitch(), /checked/u);
    const before = reloaded();
    for (const read of preferences.asked) read.answer();
    await Promise.all([first, second]);
    assert.equal(reloaded(), before + 2);
    preferences.release();
    // And the preferences do not wait for the network settings.
    network = hold("read_runtime_settings_snapshot");
    const third = appModule.handleAction("reload-settings");
    await turns();
    assert.equal(network.asked.length, 1);
    assert.equal(reloaded(), before + 3);
    network.asked[0].answer();
    await third;
  } finally {
    delete rejected.read_runtime_settings_snapshot;
    preferences?.release();
    network?.release();
    responses.read_runtime_settings_snapshot = original;
  }
});

test("Reload From Disk says that the network settings failed only when its own read did", async () => {
  const original = responses.read_runtime_settings_snapshot;
  let reads;
  try {
    await readRuntimeSettings(original);
    await renderPage("settings");
    await refuseRuntimeSettingsRead("an older refusal");
    const before = failures().length;
    reads = hold("read_runtime_settings_snapshot");
    // The reload asks, and then a refresh of the page does. The reload is
    // answered with settings, which the page does not show: it has asked
    // again since. The refusal it holds the controls for stays until the
    // refresh is answered, and it is not the reload's.
    const reload = appModule.handleAction("reload-settings");
    const refresh = emit("cfw://settings-changed", responses.read_settings_snapshot);
    await turns();
    assert.equal(reads.asked.length, 2);
    reads.asked[0].answer();
    await reload;
    assert.equal(state.runtimeSettingsError, "an older refusal");
    assert.equal(failures().length, before);
    reads.asked[1].answer();
    await refresh;
    assert.equal(state.runtimeSettingsError, null);
    // The other way round: the refresh is answered first, and the reload's
    // own read is refused after it. The page holds nothing, and the log has
    // the refusal of the reload.
    const again = appModule.handleAction("reload-settings");
    const later = emit("cfw://settings-changed", responses.read_settings_snapshot);
    await turns();
    assert.equal(reads.asked.length, 4);
    reads.asked[3].answer();
    await later;
    reads.asked[2].refuse("settings store is locked");
    await again;
    assert.equal(state.runtimeSettingsError, null);
    assert.deepEqual(failures().slice(0, 1), ["Network settings failed: settings store is locked"]);
    assert.equal(failures().length, before + 1);
  } finally {
    reads?.release();
    responses.read_runtime_settings_snapshot = original;
  }
});
