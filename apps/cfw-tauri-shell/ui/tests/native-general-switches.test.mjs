import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Channel } from "@tauri-apps/api/core";
import {
  createGeneralSwitchTransport, GENERAL_SWITCH_FRAME_LIMIT, GENERAL_SWITCH_HELP_LIMIT, GENERAL_SWITCH_KEYS,
  GENERAL_SWITCH_LABEL_LIMIT, generalSwitchFrame, resolvedGeneralAppearance,
} from "../src/native-general-switches.js";

const settle = () => new Promise((resolve) => setImmediate(resolve));
test("initial boot waits for the resolved appearance without selecting a different theme", () => {
  assert.equal(resolvedGeneralAppearance(undefined), null);
  assert.equal(resolvedGeneralAppearance("dark"), "dark");
  assert.equal(resolvedGeneralAppearance("light"), "light");
  assert.throws(() => resolvedGeneralAppearance("system"), /resolved page appearance/u);
});
const frame = () => ({ locale: "en", appearance: "light", viewport: { width: 850, height: 572 },
  clip: { x: 170, y: 0, width: 680, height: 572 }, items: [{ key: 3, label: "TUN Mode", help: "",
    enabled: true, checked: false, rect: { x: 790, y: 330, width: 34, height: 20 } }] });
function harness() {
  const calls = [], toggles = [], errors = [], ready = [], traversal = [], layout = [];
  let receive, toggleResult = Promise.resolve(), syncResult = Promise.resolve(true);
  const ui = createGeneralSwitchTransport({
    invoke: (command, args) => { calls.push({ command, args }); return command === "sync_native_general_switches" ? syncResult : Promise.resolve(true); },
    makeChannel: (handler) => { receive = handler; return {}; },
    onToggle: (key, value) => { toggles.push({ key, value }); return toggleResult; },
    onTraverse: (key, offset) => traversal.push({ key, offset }), onFocus: () => {},
    onLayout: () => layout.push(true),
    onReady: (value) => ready.push(value), onError: (error) => errors.push(String(error)),
  });
  function event(changes = {}) {
    const request = calls.find((c) => c.command === "sync_native_general_switches").args.request;
    receive({ kind: "input", requestId: request.requestId, sequence: request.sequence,
      submission: 1, key: 3, action: 1, value: true, ...changes });
  }
  return { ui, calls, toggles, errors, ready, traversal, layout, event,
    setToggle: (value) => { toggleResult = value; }, setSync: (value) => { syncResult = value; } };
}

test("General switches preserve the six original keys and one business call with delayed acknowledgement", async () => {
  assert.deepEqual(GENERAL_SWITCH_KEYS, ["allowLan", "ipv6DNS", "tunMode", "mixin", "systemProxy", "startAtLogin"]);
  const h = harness(); let finish;
  h.setToggle(new Promise((resolve) => { finish = resolve; }));
  h.ui.sync(frame()); await settle();
  h.ui.sync(frame()); await settle(); assert.equal(h.calls.length, 1);
  h.event(); await settle(); assert.deepEqual(h.toggles, [{ key: "tunMode", value: true }]);
  const moved = frame(); moved.items[0].rect.y += 4;
  h.ui.sync(moved); await settle();
  assert.equal(h.calls.at(-1).args.request.acknowledgedSubmission, 0);
  finish(); await settle(); await settle();
  assert.equal(h.calls.at(-1).args.request.acknowledgedSubmission, 1);
  assert.equal(h.calls.at(-1).args.request.items[0].checked, false, "No optimistic success state");
  assert.deepEqual(h.errors, []);
});

test("page rerender and leaving General reject old clicks while settling their native pending state", async () => {
  const h = harness(); h.ui.sync(frame()); await settle(); h.ui.invalidate();
  h.event(); await settle(); await settle(); assert.equal(h.toggles.length, 0);
  const hidden = { ...frame(), items: [] }; h.ui.sync(hidden); await settle();
  h.event({ sequence: h.ui.sequence(), submission: 2 }); await settle(); await settle();
  assert.equal(h.toggles.length, 0);
  assert.equal(h.calls.at(-1).args.request.acknowledgedSubmission, 2);
  assert.deepEqual(h.errors, []);
});

test("a submission settling behind an occluding frame cannot resurrect controls or native focus", async () => {
  const h = harness(); let finish;
  h.setToggle(new Promise((resolve) => { finish = resolve; }));
  h.ui.sync(frame()); await settle(); h.event(); await settle();
  h.ui.invalidate();
  const hidden = { ...frame(), clip: { x: 0, y: 0, width: 0, height: 0 }, items: [] };
  h.ui.sync(hidden); await settle();
  assert.equal(h.ui.canFocus(3), false);
  assert.equal(await h.ui.focus(3), false);
  h.event({ action: 2, submission: 0, value: false });
  finish(); await settle(); await settle();
  assert.deepEqual(h.calls.at(-1).args.request.items, []);
  assert.equal(h.calls.at(-1).args.request.acknowledgedSubmission, 1);
  assert.deepEqual(h.traversal, []);
  assert.equal(h.calls.some(({ command }) => command === "focus_native_general_switch"), false);
  const current = frame(); current.items[0].rect.y += 17;
  h.ui.sync(current); await settle();
  assert.equal(h.calls.at(-1).args.request.items[0].rect.y, current.items[0].rect.y);
  assert.equal(h.toggles.length, 1, "Only the submission begun before occlusion ran");
  assert.deepEqual(h.errors, []);
});

test("Tab focus does not consume or acknowledge a network submission", async () => {
  const h = harness(); h.ui.sync(frame()); await settle();
  h.event({ action: 2, submission: 0, value: false });
  h.event({ action: 3, submission: 0, value: false });
  assert.deepEqual(h.traversal, [{ key: 3, offset: 1 }, { key: 3, offset: -1 }]);
  assert.equal(h.calls.length, 1);
  h.event(); await settle(); await settle();
  assert.equal(h.toggles.length, 1);
  assert.equal(h.calls.at(-1).args.request.acknowledgedSubmission, 1);
});

test("a presentation failure closes its session and reports error instead of enabling a duplicate control", async () => {
  const h = harness(); h.setSync(Promise.reject(new Error("invalid geometry")));
  h.ui.sync(frame()); await settle(); await settle();
  assert.equal(h.ready.length, 0);
  assert.equal(h.errors.length, 1);
  assert.equal(h.calls.at(-1).command, "dismiss_native_general_switches");
  h.event(); await settle(); assert.equal(h.toggles.length, 0);
});

test("duplicate activation cannot invoke the network twice", async () => {
  const h = harness(); let finish;
  h.setToggle(new Promise((resolve) => { finish = resolve; }));
  h.ui.sync(frame()); await settle(); h.event(); await settle(); h.event(); await settle();
  assert.equal(h.toggles.length, 1); assert.equal(h.errors.length, 1);
  finish(); await settle();
  assert.equal(h.calls.at(-1).command, "dismiss_native_general_switches");
});

test("disabled native items never reach existing business handlers", async () => {
  const h = harness(), disabled = frame(); disabled.items[0].enabled = false;
  h.ui.sync(disabled); await settle(); h.event(); await settle(); await settle();
  assert.equal(h.toggles.length, 0);
  assert.equal(h.calls.at(-1).args.request.acknowledgedSubmission, 1);
});

test("identical rerender hides only the replacement DOM while preserving native focus and IPC count", async () => {
  const h = harness(); h.ui.sync(frame()); await settle();
  h.ui.invalidate(); h.ui.sync(frame()); await settle();
  assert.equal(h.calls.length, 1); assert.equal(h.ready.length, 2);
  h.event(); await settle(); await settle(); assert.equal(h.toggles.length, 1);
});

test("native geometry invalidation requests a fresh frame even at a scroll boundary", async () => {
  const h = harness(); h.ui.sync(frame()); await settle();
  h.event({ action: 5, key: 0, submission: 0, value: false });
  assert.equal(h.layout.length, 1); assert.equal(h.toggles.length, 0);
  h.ui.sync(frame(), true); await settle();
  assert.equal(h.calls.length, 2); assert.equal(h.calls.at(-1).args.request.sequence, 2);
  assert.deepEqual(h.errors, []);
});

test("focus uses its queued geometry revision even when a later refresh is waiting behind it", async () => {
  const h = harness(); h.ui.sync(frame()); await settle();
  const focus = h.ui.focus(3);
  const moved = frame(); moved.items[0].rect.y += 4; h.ui.sync(moved);
  assert.equal(await focus, true); await settle();
  const call = h.calls.find((value) => value.command === "focus_native_general_switch");
  assert.equal(call.args.sequence, 1);
  assert.equal(h.calls.at(-1).args.request.sequence, 2);
});

test("window geometry races retry with a bounded budget and never acknowledge visibility early", async () => {
  const h = harness(); h.setSync(Promise.resolve(false));
  for (let attempt = 0; attempt < 9; attempt++) { h.ui.sync(frame(), true); await settle(); }
  assert.equal(h.layout.length, 8); assert.equal(h.ready.length, 0);
  assert.equal(h.errors.length, 1);
  assert.equal(h.calls.at(-1).command, "dismiss_native_general_switches");
});

test("fresh DOM geometry resolves a stale native frame without changing switch intent", async () => {
  const h = harness(); h.setSync(Promise.resolve(false)); h.ui.sync(frame()); await settle();
  h.setSync(Promise.resolve(true));
  const resized = frame(); resized.viewport.width = 1000;
  h.ui.sync(resized); await settle();
  assert.equal(h.ready.length, 1); assert.equal(h.ready[0].items[0].checked, false);
  assert.equal(h.toggles.length, 0); assert.deepEqual(h.errors, []);
});

test("queued updates choose null only after the first presentation actually succeeds", async () => {
  const h = harness(); let finish;
  h.setSync(new Promise((resolve) => { finish = resolve; }));
  h.ui.sync(frame()); await settle();
  const moved = frame(); moved.items[0].rect.y += 1; h.ui.sync(moved);
  h.setSync(Promise.resolve(true)); finish(true); await settle(); await settle();
  assert.notEqual(h.calls[0].args.completion, null);
  assert.equal(h.calls[1].args.completion, null);
});

test("real Tauri Channel end on a rejected first frame cannot close the eventual live callback", async () => {
  const previousWindow = globalThis.window, callbacks = new Map(), ids = [], effects = [], errors = [];
  let nextId = 1, owner = null, first = true, currentRequest;
  globalThis.window = { __TAURI_INTERNALS__: {
    transformCallback: (fn) => { const id = nextId++; callbacks.set(id, fn); return id; },
    unregisterCallback: (id) => callbacks.delete(id),
  } };
  const send = (message) => callbacks.get(owner.id)?.({ index: owner.index++, message });
  try {
    const ui = createGeneralSwitchTransport({ makeChannel: (receive) => new Channel(receive),
      invoke: async (command, args) => {
        if (command !== "sync_native_general_switches") return true;
        currentRequest = args.request;
        if (owner) { assert.equal(args.completion, null, "An update must not construct another ChannelInner"); return true; }
        const id = Number(args.completion.toJSON().slice("__CHANNEL__:".length)); ids.push(id);
        assert.equal(callbacks.has(id), true, "Initial retry needs a live fresh callback");
        if (first) {
          first = false;
          callbacks.get(id)({ index: 0, end: true }); // Actual ChannelInner::drop wire shape.
          assert.equal(callbacks.has(id), false);
          return false;
        }
        owner = { id, index: 0 }; return true;
      },
      onToggle: (key, value) => effects.push({ key, value }), onReady: () => {},
      onTraverse: () => {}, onFocus: () => {}, onLayout: () => {}, onError: (e) => errors.push(String(e)),
    });
    ui.sync(frame()); await settle(); ui.sync(frame(), true); await settle();
    assert.notEqual(ids[0], ids[1]);
    for (let i = 1; i <= 3; i++) { const moved = frame(); moved.items[0].rect.y += i; ui.sync(moved); await settle(); }
    send({ kind: "input", requestId: currentRequest.requestId, sequence: currentRequest.sequence,
      key: 3, action: 1, submission: 1, value: true });
    await settle(); await settle(); assert.deepEqual(effects, [{ key: "tunMode", value: true }]);
    assert.equal(callbacks.size, 1); assert.deepEqual(errors, []);
    send({ kind: "closed", requestId: currentRequest.requestId });
    callbacks.get(owner.id)({ index: owner.index, end: true });
    await settle(); assert.equal(callbacks.size, 0);
    assert.match(errors[0], /closed before/u);
  } finally {
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
  }
});

// General gives the reason of a failed read of the network settings to its
// Allow LAN and IPv6 DNS switches, and a reason quotes the host. The host
// refuses a frame whose text is over its limits, which ends every native
// switch of the window, so the page keeps each frame within them.
const RECT = Object.freeze({ x: 790, y: 330, width: 34, height: 20 });
const BASE = Object.freeze({ locale: "en", appearance: "light", viewport: { width: 1100, height: 760 },
  clip: { x: 0, y: 0, width: 1100, height: 760 }, items: [] });
const held = (key, title, name) => ({ key, name, title, checked: false, enabled: false, rect: RECT });
// The IPv6 DNS switch as the native layer gets it when the page holds it for `title`.
const ipv6Switch = (title, name = "IPv6 DNS") => {
  const frame = generalSwitchFrame(BASE, [held(2, title, name)]);
  assert.deepEqual({ ...frame, items: [] }, BASE);
  assert.deepEqual(frame.items.map(({ label, help, ...rest }) => rest), [{ key: 2, checked: false, enabled: false, rect: RECT }]);
  return { label: frame.items[0].label, help: frame.items[0].help };
};

test("the page's limits of a native switches frame are the host's", () => {
  const host = readFileSync(new URL("../../src/native_components/general_switches.rs", import.meta.url), "utf8");
  assert.match(host, /\|\| item\.label\.chars\(\)\.count\(\) > 160\n/u);
  assert.match(host, /\|\| item\.help\.chars\(\)\.count\(\) > 1024\n/u);
  assert.match(host, /\|\| serde_json::to_vec\(self\)\.map_err\(\|e\| e\.to_string\(\)\)\?\.len\(\) > 15_500\n/u);
  assert.deepEqual([GENERAL_SWITCH_LABEL_LIMIT, GENERAL_SWITCH_HELP_LIMIT, GENERAL_SWITCH_FRAME_LIMIT], [160, 1024, 15_500]);
});

test("a reason longer than the host takes as help is cut for the native switch", () => {
  // What fits is passed on as it is, and a switch without a reason has no help.
  const fits = "x".repeat(1024);
  assert.deepEqual(ipv6Switch(fits), { label: "IPv6 DNS", help: fits });
  assert.deepEqual(ipv6Switch(""), { label: "IPv6 DNS", help: "" });
  // What the host says of a settings file with a long unknown field.
  const long = `unknown field \`${"k".repeat(1100)}\`, expected one of \`log_level\`, \`allow_lan\``;
  assert.deepEqual(ipv6Switch(long), { label: "IPv6 DNS", help: `${long.slice(0, 1023)}\u2026` });
  // The host counts characters, so one outside the basic plane counts once
  // and is never cut in half.
  const wide = "\u{1D4B3}";
  assert.equal(ipv6Switch(wide.repeat(1024)).help, wide.repeat(1024));
  const cut = ipv6Switch(wide.repeat(1025)).help;
  assert.equal(cut, `${wide.repeat(1023)}\u2026`);
  assert.equal(cut.isWellFormed(), true);
});

test("the name of a native switch is the one the page gives it, within the host's limit", () => {
  // Whatever the reason is. The name used to be looked for in the text that
  // the page says of a switch, before the reason, and was not found when the
  // reason ended in a line break or held a character that a browser keeps
  // differently in a tooltip and in text.
  assert.deepEqual(ipv6Switch("settings store is locked\n"), { label: "IPv6 DNS", help: "settings store is locked\n" });
  assert.deepEqual(ipv6Switch(`\uFFFD${"k".repeat(400)}`), { label: "IPv6 DNS", help: `\uFFFD${"k".repeat(400)}` });
  // A name over the host's limit is cut as a reason is.
  assert.equal(ipv6Switch("", "n".repeat(160)).label, "n".repeat(160));
  assert.equal(ipv6Switch("", "n".repeat(161)).label, `${"n".repeat(159)}\u2026`);
});

test("a frame is built without reading a long reason through", () => {
  // General builds a frame whenever the page scrolls, and a reason is as long
  // as the diagnostic it quotes. This text notes how far it was read and
  // cannot be taken whole.
  const watched = (text) => {
    const seen = { characters: 0 };
    const note = (end) => { seen.characters = Math.max(seen.characters, end); };
    return { seen, text: {
      length: text.length,
      codePointAt(index) { note(index + 1); return text.codePointAt(index); },
      charCodeAt(index) { note(index + 1); return text.charCodeAt(index); },
      slice(start, end = text.length) { note(end); return text.slice(start, end); },
      substring(start, end = text.length) { note(end); return text.substring(start, end); },
      toString() { throw new Error("the whole text was read"); },
    } };
  };
  const reason = watched("r".repeat(1 << 21)), name = watched("n".repeat(1 << 12));
  const [item] = generalSwitchFrame(BASE, [held(2, reason.text, name.text)]).items;
  assert.deepEqual([item.label, item.help], [`${"n".repeat(159)}\u2026`, `${"r".repeat(1023)}\u2026`]);
  assert.deepEqual([name.seen.characters, reason.seen.characters], [GENERAL_SWITCH_LABEL_LIMIT, GENERAL_SWITCH_HELP_LIMIT]);
});

test("a frame over the host's size loses the second half of its longest help until it fits", () => {
  const frame = (helps) => generalSwitchFrame(BASE, helps.map((help, index) => held(index + 1, help, "Switch")));
  const bytes = (value) => Buffer.byteLength(JSON.stringify(value));
  const helps = (value) => value.items.map((item) => item.help);
  // The host measures a frame with the transport's two counters, at most 70
  // bytes, and with a fraction on each of its 30 measures, at most 3 bytes
  // each. The page sets 256 bytes aside for them.
  const room = GENERAL_SWITCH_FRAME_LIMIT - 256 - bytes(frame(["", "", "", "", "", ""]));
  // Two reasons of the longest help the host takes, each character of them
  // six bytes in the frame, and plain text that fills the rest to the byte.
  const wide = "\u0001".repeat(1024);
  const rest = room - 2 * 6 * 1024;
  assert.ok(rest > 2048 && rest < 3072, `${rest} bytes are left`);
  const full = [wide, wide, "a".repeat(1024), "b".repeat(1024), "c".repeat(rest - 2048), ""];
  assert.equal(bytes(frame(full)) + 256, GENERAL_SWITCH_FRAME_LIMIT);
  assert.deepEqual(helps(frame(full)), full);
  // With one byte more, the longest help is cut in half and no other.
  const over = [wide, wide, "a".repeat(1024), "b".repeat(1024), "c".repeat(rest - 2047), ""];
  assert.deepEqual(helps(frame(over)), [`${"\u0001".repeat(511)}\u2026`, ...over.slice(1)]);
  // The most the page can ask for: such a reason on every switch.
  const worst = frame(GENERAL_SWITCH_KEYS.map(() => wide));
  assert.ok(bytes(worst) + 256 <= GENERAL_SWITCH_FRAME_LIMIT, `${bytes(worst)} bytes`);
  for (const help of helps(worst)) assert.match(help, /^\u0001{255,}\u2026$/u, "a switch keeps the beginning of its help");
});
