import test from "node:test";
import assert from "node:assert/strict";
import { Channel } from "@tauri-apps/api/core";
import { createGeneralSwitchTransport, GENERAL_SWITCH_KEYS, resolvedGeneralAppearance } from "../src/native-general-switches.js";

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
