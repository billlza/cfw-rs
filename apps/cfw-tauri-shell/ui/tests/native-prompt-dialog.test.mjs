import test from "node:test";
import assert from "node:assert/strict";
import { createNativePromptDialog, promptDialogFrame } from "../src/native-prompt-dialog.js";

const settle = () => new Promise((resolve) => setImmediate(resolve));
const BUTTONS = [{ id: "cancel", title: "No", role: "cancel" }, { id: "confirm", title: "Yes", role: "destructive" }];
const frame = (changes = {}) => ({ title: "Delete profile", message: "Delete “Work”?", buttons: BUTTONS, ...changes });
const commands = (h) => h.calls.map(({ command }) => command);

function harness() {
  const calls = [], callbacks = [], activated = [], errors = [];
  const replies = { present: () => Promise.resolve(), update: () => Promise.resolve(true), dismiss: () => Promise.resolve(true) };
  let closes = 0, changes = 0, action = () => undefined;
  const ui = createNativePromptDialog({ enabled: () => true,
    invoke: (command, args) => { calls.push({ command, args }); return replies[command.split("_")[0]](); },
    makeChannel: (callback) => { callbacks.push(callback); return {}; },
    onError: (error, title) => errors.push({ message: String(error), title }),
  });
  const handlers = {
    onActivate: (buttonId) => { activated.push(buttonId); return action(buttonId); },
    onClose: () => { closes++; }, onChange: () => { changes++; },
  };
  return { ui, calls, callbacks, activated, errors, handlers, replies,
    setPresent: (next) => { replies.present = next; }, setAction: (next) => { action = next; },
    closes: () => closes, changes: () => changes };
}

async function presented(h, dialog = {}) {
  h.ui.sync(dialog, frame(), h.handlers);
  await settle();
  return { dialog, requestId: h.calls[0].args.request.requestId };
}

test("an activation is acknowledged only after the dashboard finished it, and close ends the session", async () => {
  const h = harness();
  const { dialog, requestId } = await presented(h);
  assert.deepEqual(h.calls[0].args.request, { requestId, sequence: 1, acknowledgedSubmission: 0, ...frame() });
  assert.match(requestId, /^[0-9a-f-]{36}$/u);
  h.ui.sync(dialog, frame(), h.handlers);
  await settle();
  assert.equal(h.calls.length, 1, "an unchanged frame is not sent again");

  let finish;
  h.setAction(() => new Promise((resolve) => { finish = resolve; }));
  h.callbacks[0]({ requestId, kind: "activate", submissionId: 1, buttonId: "confirm" });
  assert.deepEqual(h.activated, ["confirm"]);
  h.ui.sync(dialog, frame({ title: "プロファイルを削除" }), h.handlers);
  await settle();
  assert.equal(h.calls[1].command, "update_native_prompt_dialog");
  assert.equal(h.calls[1].args.request.sequence, 2);
  assert.equal(h.calls[1].args.request.acknowledgedSubmission, 0, "a running action is not acknowledged by a language change");
  assert.equal(h.changes(), 0);

  finish();
  await settle();
  assert.equal(h.changes(), 1, "the settled action asks the dashboard to render its acknowledgement");
  h.ui.sync(dialog, frame({ title: "プロファイルを削除" }), h.handlers);
  await settle();
  assert.equal(h.calls[2].command, "update_native_prompt_dialog");
  assert.equal(h.calls[2].args.request.sequence, 3);
  assert.equal(h.calls[2].args.request.acknowledgedSubmission, 1);
  h.ui.sync(dialog, frame({ title: "プロファイルを削除" }), h.handlers);
  await settle();
  assert.equal(h.calls.length, 3, "an acknowledgement is sent once");

  h.callbacks[0]({ requestId, kind: "activate", submissionId: 2, buttonId: "confirm" });
  await settle();
  assert.deepEqual(h.activated, ["confirm", "confirm"]);
  h.callbacks[0]({ requestId, kind: "closed" });
  h.callbacks[0]({ requestId, kind: "activate", submissionId: 3, buttonId: "confirm" });
  await settle();
  assert.equal(h.closes(), 1);
  assert.equal(h.activated.length, 2, "a closed session cannot activate");
  assert.equal(h.errors.length, 0);
  assert.equal(commands(h).includes("dismiss_native_prompt_dialog"), false, "a panel that closed itself is not dismissed again");
});

test("malformed, unknown, replayed and overlapping results are explicit failures that never run an action", async () => {
  const invalid = (requestId) => [
    null,
    { requestId, kind: "closed", extra: true },
    { requestId: "another-request", kind: "closed" },
    { requestId, kind: "submit", submissionId: 1, buttonId: "confirm" },
    { requestId, kind: "activate", submissionId: 1, buttonId: "cancel" },
    { requestId, kind: "activate", submissionId: 1, buttonId: "delete" },
    { requestId, kind: "activate", submissionId: 0, buttonId: "confirm" },
    { requestId, kind: "activate", submissionId: "1", buttonId: "confirm" },
    { requestId, kind: "activate", submissionId: 1, buttonId: "confirm", command: "delete_profile" },
    { requestId, kind: "activate", submissionId: 1 },
    { requestId: "another-request", kind: "activate", submissionId: 1, buttonId: "confirm" },
  ];
  for (let index = 0; index < invalid("").length; index++) {
    const h = harness();
    const { dialog, requestId } = await presented(h);
    h.callbacks[0](invalid(requestId)[index]);
    await settle();
    assert.match(h.ui.sync(dialog, frame(), h.handlers), /invalid result/u, `case ${index}`);
    assert.deepEqual(h.errors, [{ message: "Error: Native prompt dialog returned an invalid result", title: "Delete profile" }]);
    assert.equal(h.changes(), 1);
    assert.equal(h.closes(), 0);
    assert.deepEqual(h.activated, []);
    assert.deepEqual(commands(h), ["present_native_prompt_dialog", "dismiss_native_prompt_dialog"]);
    h.ui.sync(null);
    await settle();
    assert.equal(commands(h).filter((command) => command === "dismiss_native_prompt_dialog").length, 1);
  }

  const h = harness();
  const { dialog, requestId } = await presented(h);
  h.setAction(() => new Promise(() => {}));
  h.callbacks[0]({ requestId, kind: "activate", submissionId: 1, buttonId: "confirm" });
  h.callbacks[0]({ requestId, kind: "activate", submissionId: 2, buttonId: "confirm" });
  await settle();
  assert.deepEqual(h.activated, ["confirm"], "a second activation cannot overlap the first");
  assert.match(h.ui.sync(dialog, frame(), h.handlers), /invalid result/u);
});

test("a superseded or closed dialog is dismissed and its late results are ignored", async () => {
  const h = harness();
  const first = await presented(h);
  const second = {};
  h.ui.sync(second, frame({ title: "Reset all settings" }), h.handlers);
  await settle();
  assert.deepEqual(commands(h), ["present_native_prompt_dialog", "dismiss_native_prompt_dialog", "present_native_prompt_dialog"]);
  assert.equal(h.calls[1].args.requestId, first.requestId);
  assert.notEqual(h.calls[2].args.request.requestId, first.requestId);
  assert.equal(h.calls[2].args.request.title, "Reset all settings");
  h.callbacks[0]({ requestId: first.requestId, kind: "activate", submissionId: 1, buttonId: "confirm" });
  h.callbacks[0]({ requestId: first.requestId, kind: "closed" });
  assert.deepEqual(h.activated, []);
  assert.equal(h.closes(), 0);
  h.ui.sync(null);
  await settle();
  assert.equal(h.calls.at(-1).command, "dismiss_native_prompt_dialog");
  assert.equal(h.calls.at(-1).args.requestId, h.calls[2].args.request.requestId);
  h.ui.sync(null);
  await settle();
  assert.equal(h.calls.length, 4, "nothing is dismissed twice");
  assert.equal(h.errors.length, 0);
});

test("closing during presentation dismisses after the host admitted it", async () => {
  const h = harness();
  let admit;
  const admission = new Promise((resolve) => { admit = resolve; });
  h.setPresent(() => admission);
  h.ui.sync({}, frame(), h.handlers);
  await settle();
  const requestId = h.calls[0].args.request.requestId;
  h.ui.sync(null);
  h.callbacks[0]({ requestId, kind: "activate", submissionId: 1, buttonId: "confirm" });
  await settle();
  assert.deepEqual(h.activated, []);
  assert.deepEqual(commands(h), ["present_native_prompt_dialog"],
    "a dismissal sent before the host admitted the panel would find nothing and leave it on screen");
  admit(); await settle();
  assert.deepEqual(commands(h), ["present_native_prompt_dialog", "dismiss_native_prompt_dialog"]);
  assert.equal(h.calls[1].args.requestId, requestId);
});

test("a refused presentation or action is reported with its dialog and leaves a cancellation path", async () => {
  const refused = harness();
  refused.setPresent(() => Promise.reject(new Error("native prompt dialog presentation rejected (status 0)")));
  const dialog = {};
  refused.ui.sync(dialog, frame(), refused.handlers);
  await settle();
  assert.equal(refused.ui.sync(dialog, frame(), refused.handlers), "native prompt dialog presentation rejected (status 0)");
  assert.deepEqual(refused.errors, [{ message: "Error: native prompt dialog presentation rejected (status 0)", title: "Delete profile" }]);
  assert.equal(refused.changes(), 1);
  await settle();
  assert.deepEqual(commands(refused), ["present_native_prompt_dialog", "dismiss_native_prompt_dialog"]);

  const thrown = harness();
  const active = await presented(thrown);
  thrown.setAction(() => { throw new Error("Prompt dialog button confirm has no action"); });
  thrown.callbacks[0]({ requestId: active.requestId, kind: "activate", submissionId: 1, buttonId: "confirm" });
  await settle();
  assert.equal(thrown.ui.sync(active.dialog, frame(), thrown.handlers), "Prompt dialog button confirm has no action");
  assert.equal(thrown.errors.length, 1);
  assert.equal(thrown.closes(), 0);
  thrown.callbacks[0]({ requestId: active.requestId, kind: "closed" });
  assert.equal(thrown.closes(), 0, "the dashboard closes a failed dialog; its native close is not a user choice");

  const late = harness();
  let refuse;
  const admission = new Promise((_, reject) => { refuse = reject; });
  late.setPresent(() => admission);
  late.ui.sync({}, frame(), late.handlers);
  await settle();
  late.ui.sync(null);
  refuse(new Error("native prompt dialog renderer reloaded"));
  await settle();
  assert.deepEqual(late.errors, [{ message: "Error: native prompt dialog renderer reloaded", title: "Delete profile" }],
    "a refusal that arrives after its dialog closed is still reported");
  assert.equal(late.changes(), 0, "a closed dialog has nothing left to render");
});

test("a refused update fails the dialog and a refused dismissal is reported, never swallowed", async () => {
  const h = harness();
  const { dialog } = await presented(h);
  h.replies.update = () => Promise.reject(new Error("native prompt dialog update rejected (status 0)"));
  assert.equal(h.ui.sync(dialog, frame({ title: "Reset all settings" }), h.handlers), null);
  await settle();
  assert.equal(h.ui.sync(dialog, frame({ title: "Reset all settings" }), h.handlers), "native prompt dialog update rejected (status 0)");
  assert.deepEqual(h.errors, [{ message: "Error: native prompt dialog update rejected (status 0)", title: "Reset all settings" }]);
  assert.equal(h.changes(), 1);
  assert.deepEqual(commands(h), ["present_native_prompt_dialog", "update_native_prompt_dialog", "dismiss_native_prompt_dialog"]);

  const stuck = harness();
  await presented(stuck);
  stuck.replies.dismiss = () => Promise.reject(new Error("native prompt dialog dismissal rejected (status 3)"));
  stuck.ui.sync(null);
  await settle();
  assert.deepEqual(stuck.errors, [{ message: "Error: native prompt dialog dismissal rejected (status 3)", title: "Delete profile" }]);
  assert.equal(stuck.changes(), 0);
  stuck.ui.sync(null);
  await settle();
  assert.equal(stuck.errors.length, 1, "nothing is left to retry once the dashboard has no dialog");
});

test("a failed dialog cannot act while its panel is still on screen", async () => {
  const h = harness();
  const { dialog, requestId } = await presented(h);
  // The dismissal that follows the failure has not landed, so the panel can
  // still be clicked while the page shows "failure, dismissal only".
  h.replies.dismiss = () => new Promise(() => {});
  h.replies.update = () => Promise.reject(new Error("native prompt dialog update rejected (status 0)"));
  h.ui.sync(dialog, frame({ title: "Reset all settings" }), h.handlers);
  await settle();
  assert.match(h.ui.sync(dialog, frame({ title: "Reset all settings" }), h.handlers), /update rejected/u);
  h.callbacks[0]({ requestId, kind: "activate", submissionId: 1, buttonId: "confirm" });
  h.callbacks[0]({ requestId, kind: "activate", submissionId: 7, buttonId: "delete" });
  await settle();
  assert.deepEqual(h.activated, [], "a failed presentation never runs the action");
  assert.equal(h.errors.length, 1, "and reports its failure once");
  assert.equal(h.changes(), 1);
  h.callbacks[0]({ requestId, kind: "closed" });
  assert.equal(h.closes(), 0, "the dashboard, not the failed panel, closes the dialog");
});

test("frames carry only what the bounded native contract admits", () => {
  globalThis.document = { documentElement: { dataset: { theme: "dark" } } };
  const prompt = (changes = {}) => ({ title: "Delete profile", message: "Delete “Work”?",
    buttons: [BUTTONS[0], { ...BUTTONS[1], activate: () => assert.fail("a frame never runs an action") }], ...changes });
  assert.deepEqual(promptDialogFrame(prompt()), {
    locale: "en", appearance: "dark", title: "Delete profile", message: "Delete “Work”?", buttons: BUTTONS,
    transportFailure: "The native dialog could not deliver this action. Close it and try again.",
  });
  assert.equal(promptDialogFrame(prompt({ message: "" })).message, "", "a notice may carry a title only");
  assert.equal(promptDialogFrame(prompt({ title: "字".repeat(160), message: "字".repeat(4096) })).message.length, 4096);
  // The unit is the Unicode scalar: 160 astral characters are 320 UTF-16
  // units and fit, while 161 scalars do not, whatever their UTF-16 length.
  assert.equal(Array.from(promptDialogFrame(prompt({ title: "\u{1F512}".repeat(160) })).title).length, 160);
  for (const outside of [
    { title: "" }, { title: " \n" }, { title: "x".repeat(161) }, { title: undefined },
    { title: "\u{1F512}".repeat(159) + "ab" }, { title: "\u{1F512}".repeat(161) },
    { message: "x".repeat(4097) }, { message: undefined }, { message: 7 },
    // Within every text bound, yet larger than the frame the panel accepts.
    { message: "\u{1F512}".repeat(4096) },
    // A lone surrogate has no UTF-8 form to send.
    { title: "Delete \ud800" }, { message: "\udc00 profile" },
    { buttons: [BUTTONS[0], { ...BUTTONS[1], title: "\ud83d" }] },
    { buttons: [{ ...BUTTONS[0], title: " " }] },
    { buttons: [BUTTONS[0], { ...BUTTONS[1], title: "x".repeat(161) }] },
  ]) assert.equal(promptDialogFrame(prompt(outside)), null, JSON.stringify(outside).slice(0, 60));

  const expand = Array.from;
  let expansions = 0;
  Array.from = function counted(...values) { expansions += 1; return expand.apply(this, values); };
  try {
    assert.equal(promptDialogFrame(prompt({ title: "x".repeat(2 * 160 + 1) })), null);
    assert.equal(expansions, 0, "a string that cannot fit is refused before it is expanded");
  } finally { Array.from = expand; }

  // Until the page theme is resolved there is no appearance to give the panel.
  for (const theme of [undefined, "system", ""]) {
    globalThis.document = { documentElement: { dataset: { theme } } };
    assert.equal(promptDialogFrame(prompt()), null, `theme ${theme}`);
  }
  globalThis.document = { documentElement: { dataset: { theme: "light" } } };
  assert.equal(promptDialogFrame(prompt()).appearance, "light");
});
