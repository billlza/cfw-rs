// The General page's switches as the native layer of macOS gets them, taken
// from the page as the application renders it and judged as the host judges a
// frame.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  RUNNING_ENGINE, element, invocationDetails, invoked, page, querySelectorAllElements,
  querySelectorElements, rejected, renderPage, responses, setEngine, state,
} from "./support/render-harness.mjs";
import { readRuntimeSettings } from "./support/runtime-settings-reads.mjs";

const KEYS = ["allowLan", "ipv6DNS", "tunMode", "mixin", "systemProxy", "startAtLogin"];
const HOST = readFileSync(new URL("../../src/native_components/general_switches.rs", import.meta.url), "utf8");
const hostLimit = (pattern) => Number(HOST.match(pattern)[1].replaceAll("_", ""));
const LABEL_LIMIT = hostLimit(/item\.label\.chars\(\)\.count\(\) > (\d+)\n/u);
const HELP_LIMIT = hostLimit(/item\.help\.chars\(\)\.count\(\) > (\d+)\n/u);
const FRAME_LIMIT = hostLimit(/serde_json::to_vec\(self\)\.map_err\(\|e\| e\.to_string\(\)\)\?\.len\(\) > ([\d_]+)\n/u);
assert.deepEqual([LABEL_LIMIT, HELP_LIMIT, FRAME_LIMIT], [160, 1024, 15_500]);

/// What the host does with the text of a frame it is asked to show. It
/// measures the frame as it writes it, without the request's identity and
/// with up to three more bytes on each of the frame's measures, so this is
/// never more lenient than the host.
function admit({ request }) {
  const { requestId: _, ...frame } = request;
  const measures = 6 + 4 * frame.items.length;
  if (frame.items.some((item) => item.label.trim() === "" || Array.from(item.label).length > LABEL_LIMIT
    || Array.from(item.help).length > HELP_LIMIT)
    || Buffer.byteLength(JSON.stringify(frame)) + 3 * measures > FRAME_LIMIT) {
    throw new Error("invalid native General switches frame");
  }
  return true;
}

const plain = (html) => html.replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&quot;", '"')
  .replaceAll("&#039;", "'").replaceAll("&amp;", "&");
/// One switch of the page as it is rendered now: its name, its tooltip and
/// the attributes of its checkbox.
function rendered(key) {
  const found = page.innerHTML.match(new RegExp(`<label class="inline-switch[^"]*"([^>]*)>\\s*`
    + `<span class="visually-hidden">[^<]*</span>\\s*<input type="checkbox" data-toggle="${key}"([^>]*)/>`, "u"));
  assert.ok(found, `${key} is on the page`);
  const attribute = (name) => plain(found[1].match(new RegExp(` ${name}="([^"]*)"`, "u"))?.[1] ?? "");
  return { name: attribute("data-switch-name"), title: attribute("title"), input: found[2] };
}
/// The elements a browser would give the native layer for that switch.
function row(key, index) {
  const label = element("label"), input = element("input");
  label.classList = { add() {}, remove() {} };
  label.setAttribute = () => {};
  label.removeAttribute = () => {};
  Object.defineProperty(label.dataset, "switchName", { get: () => rendered(key).name });
  label.getBoundingClientRect = () => ({ x: 790, y: 80 + index * 40, width: 34, height: 20 });
  Object.defineProperty(label, "title", { get: () => rendered(key).title });
  input.dataset.toggle = key;
  input.closest = () => label;
  input.removeAttribute = (name) => { if (name === "data-native-general-key") delete input.dataset.nativeGeneralKey; };
  Object.defineProperty(input, "checked", { get: () => /\bchecked\b/u.test(rendered(key).input) });
  Object.defineProperty(input, "disabled", { get: () => /\bdisabled\b/u.test(rendered(key).input) });
  return input;
}

test("a long diagnostic of a refused settings read does not end the native switches", async () => {
  const prior = { resize: globalThis.ResizeObserver, style: globalThis.getComputedStyle,
    frame: globalThis.requestAnimationFrame, events: window.addEventListener,
    enabled: state.payload.native_ui.general_switches, engine: responses.engine_snapshot };
  const general = element();
  general.parentElement = null;
  querySelectorElements.set(".cfw-general-view", general);
  querySelectorAllElements.set(".cfw-general-view .inline-switch input[data-toggle]", KEYS.map(row));
  globalThis.ResizeObserver = class { observe() {} disconnect() {} };
  globalThis.getComputedStyle = () => ({ overflowX: "visible", overflowY: "visible" });
  globalThis.requestAnimationFrame = (callback) => setImmediate(callback);
  window.addEventListener = () => {};
  responses.sync_native_general_switches = admit;
  responses.focus_native_general_switch = true;
  responses.dismiss_native_general_switches = true;
  const frames = () => invocationDetails.filter(({ command }) => command === "sync_native_general_switches").map(({ args }) => args.request);
  // The two switches of the network settings as the native layer has them.
  const shown = () => frames().at(-1).items.slice(0, 2).map(({ key, label, help, checked, enabled }) => ({ key, label, help, checked, enabled }));
  const settle = async () => {
    for (let turn = 0; turn < 8; turn += 1) await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setTimeout(resolve, 20));
  };
  const hint = "Enable IPv6 address resolution. Changes are applied and saved; existing connections may reconnect.";
  // What the host says of a settings file with a long unknown field. Like
  // other diagnostics that quote a file, it ends in a line break.
  const long = `invalid runtime settings: unknown field \`${"k".repeat(1100)}\`, expected one of \`log_level\`, \`allow_lan\`\n`;
  assert.ok(long.length > HELP_LIMIT);
  let original;
  try {
    state.payload.native_ui.general_switches = true;
    await setEngine(RUNNING_ENGINE);
    original = responses.read_runtime_settings_snapshot;
    await renderPage("general"); await settle();
    assert.equal(frames().at(-1).items.length, 6);
    assert.deepEqual(shown(), [
      { key: 1, label: "Allow LAN", help: "", checked: false, enabled: true },
      { key: 2, label: "IPv6 DNS", help: hint, checked: true, enabled: true },
    ]);
    // The native IPv6 DNS switch is clicked, and the host refuses the read of
    // the settings that the click begins with.
    rejected.read_runtime_settings_snapshot = long;
    const { requestId, sequence } = frames().at(-1);
    const completion = invocationDetails.find(({ command }) => command === "sync_native_general_switches").args.completion;
    completion.onmessage({ kind: "input", requestId, sequence, submission: 1, key: 2, action: 1, value: false });
    await settle();
    assert.equal(state.runtimeSettingsError, long);
    assert.ok(state.logs.some((entry) => entry.message === `ipv6DNS refused: ${long}`), "the log has the whole diagnostic");
    assert.ok(page.innerHTML.includes(`title="${long}"`), "and so has the page, as a tooltip");
    // Both switches are held with the reason, and the native layer still has them.
    const reason = `${long.slice(0, HELP_LIMIT - 1)}\u2026`;
    assert.deepEqual(shown(), [
      { key: 1, label: "Allow LAN", help: reason, checked: false, enabled: false },
      { key: 2, label: "IPv6 DNS", help: reason, checked: false, enabled: false },
    ]);
    assert.equal(state.nativeGeneralPresentationError ?? null, null);
    assert.ok(!invoked.includes("dismiss_native_general_switches"));
    // The settings are read again, and the switches are the native ones still.
    delete rejected.read_runtime_settings_snapshot;
    await readRuntimeSettings(original); await settle();
    assert.deepEqual(shown(), [
      { key: 1, label: "Allow LAN", help: "", checked: false, enabled: true },
      { key: 2, label: "IPv6 DNS", help: hint, checked: true, enabled: true },
    ]);
    assert.equal(state.nativeGeneralPresentationError ?? null, null);
    assert.ok(!invoked.includes("dismiss_native_general_switches"));
  } finally {
    delete rejected.read_runtime_settings_snapshot;
    if (original) responses.read_runtime_settings_snapshot = original;
    await renderPage("feedback"); await settle();
    state.payload.native_ui.general_switches = prior.enabled;
    querySelectorElements.delete(".cfw-general-view");
    querySelectorAllElements.delete(".cfw-general-view .inline-switch input[data-toggle]");
    globalThis.ResizeObserver = prior.resize;
    globalThis.getComputedStyle = prior.style;
    globalThis.requestAnimationFrame = prior.frame;
    window.addEventListener = prior.events;
    await setEngine(prior.engine);
  }
});
