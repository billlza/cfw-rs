import test from "node:test";
import assert from "node:assert/strict";
import { createNativeRuntimeSettings } from "../src/native-runtime-settings.js";

const settle = () => new Promise((resolve) => setImmediate(resolve));
function harness() {
  const calls = [], callbacks = [], submitted = [], errors = [];
  let present = Promise.resolve(), closes = 0, changes = 0;
  const ui = createNativeRuntimeSettings({ enabled: () => true,
    invoke: (command, args) => { calls.push({ command, args }); return command === "present_native_runtime_settings" ? present : Promise.resolve(true); },
    makeChannel: (callback) => { callbacks.push(callback); return {}; },
    onError: (error) => errors.push(String(error)),
  });
  const handlers = { onSubmit: (draft) => submitted.push(draft), onClose: () => { closes++; }, onChange: () => { changes++; } };
  return { ui, calls, callbacks, submitted, errors, handlers,
    setPresent: (promise) => { present = promise; }, closes: () => closes, changes: () => changes };
}

test("native settings sends only changed frames and returns submit without closing the dialog", async () => {
  const h = harness(), dialog = {}, frame = { saving: false, error: null };
  h.ui.sync(dialog, frame, h.handlers);
  await settle();
  const requestId = h.calls[0].args.request.requestId;
  h.ui.sync(dialog, { ...frame }, h.handlers);
  await settle();
  assert.equal(h.calls.length, 1);
  h.callbacks[0]({ requestId, kind: "submit", submissionId: 1, draft: { port: "8990" } });
  assert.deepEqual(h.submitted, [{ port: "8990" }]);
  assert.equal(h.closes(), 0);
  h.ui.sync(dialog, { saving: true, error: null }, h.handlers);
  await settle();
  assert.equal(h.calls[1].args.request.sequence, 2);
  h.ui.sync(dialog, { saving: false, error: "revision conflict" }, h.handlers);
  await settle();
  assert.equal(h.calls[2].args.request.sequence, 3);
  h.callbacks[0]({ requestId, kind: "closed" });
  h.callbacks[0]({ requestId, kind: "submit", submissionId: 1, draft: { port: "9000" } });
  assert.equal(h.closes(), 1);
  assert.equal(h.submitted.length, 1);
});

test("closing during presentation dismisses after acknowledgement and ignores obsolete submissions", async () => {
  const h = harness();
  let admit;
  h.setPresent(new Promise((resolve) => { admit = resolve; }));
  h.ui.sync({}, { saving: false }, h.handlers);
  await settle();
  const requestId = h.calls[0].args.request.requestId;
  h.ui.sync(null);
  h.callbacks[0]({ requestId, kind: "submit", submissionId: 1, draft: {} });
  assert.equal(h.submitted.length, 0);
  admit(); await settle();
  assert.deepEqual(h.calls.map(({ command }) => command), ["present_native_runtime_settings", "dismiss_native_runtime_settings"]);
  assert.equal(h.calls[1].args.requestId, requestId);
});

test("malformed settings callbacks remain explicit failures with an available cancellation path", async () => {
  const h = harness(), dialog = {}, frame = { saving: false };
  h.ui.sync(dialog, frame, h.handlers);
  await settle();
  const requestId = h.calls[0].args.request.requestId;
  h.callbacks[0]({ requestId, kind: "closed", extra: true });
  await settle();
  assert.match(h.ui.sync(dialog, frame, h.handlers), /invalid result/u);
  assert.equal(h.errors.length, 1);
  assert.equal(h.changes(), 1);
  assert.equal(h.closes(), 0);
  assert.equal(h.submitted.length, 0);
  h.ui.sync(null);
  await settle();
  assert.equal(h.calls.filter(({ command }) => command === "dismiss_native_runtime_settings").length, 1);
});

test("repeating an invalid submit acknowledges the same error instead of leaving the native form busy", async () => {
  const h = harness(), dialog = {}, failedFrame = { saving: false, error: "trusted LAN ranges required" };
  h.ui.sync(dialog, failedFrame, h.handlers);
  await settle();
  const requestId = h.calls[0].args.request.requestId;
  for (let sequence = 2; sequence <= 3; sequence++) {
    h.callbacks[0]({ requestId, kind: "submit", submissionId: sequence - 1, draft: { allow: true, lanSources: "" } });
    h.ui.sync(dialog, failedFrame, h.handlers);
    await settle();
    assert.equal(h.calls.at(-1).command, "update_native_runtime_settings");
    assert.equal(h.calls.at(-1).args.request.sequence, sequence);
    assert.equal(h.calls.at(-1).args.request.acknowledgedSubmission, sequence - 1);
  }
});
