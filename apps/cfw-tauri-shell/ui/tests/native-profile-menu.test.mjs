import assert from "node:assert/strict";
import test from "node:test";
import { createNativeProfileMenu, nativeMenuItems, profileMenuItems } from "../src/native-profile-menu.js";

const actions = [
  { id: "select", label: "Select", icon: "check", needsInactive: true },
  { id: "edit", label: "Edit", icon: "edit" },
  { id: "update", label: "Update", icon: "refresh", remoteOnly: true },
  { id: "credentials", label: "Credentials", icon: "gear", needsEngineOff: true },
  { id: "delete", label: "Delete", icon: "trash", danger: true },
];
const t = (key, args = {}) => key.replace("{sourceError}", args.sourceError);
const options = (engineOff) => ({ engineOff, engineNotOffReason: "Stop the engine first", t });

test("native material keeps original action ordering, hidden selection and disabled reasons", () => {
  for (const active of [false, true]) {
    for (const engineOff of [false, true]) {
      for (const sourceUrl of [undefined, null, "https://example.test/profile"]) {
        const items = profileMenuItems(actions, { active, sourceUrl }, options(engineOff));
        assert.deepEqual(items.map(({ id }) => id), actions.filter((a) => !(a.needsInactive && active)).map(({ id }) => id));
        assert.equal(items.find(({ id }) => id === "credentials").reason, engineOff ? null : "Stop the engine first");
        const update = items.find(({ id }) => id === "update");
        assert.equal(update.reason, sourceUrl === undefined ? "Reading this profile…" : sourceUrl === null ? "This profile was imported locally and has no subscription URL." : null);
        const native = nativeMenuItems(items);
        assert.equal(native.find(({ id }) => id === "update").enabled, sourceUrl !== undefined && sourceUrl !== null);
        assert.ok(native.at(-1).danger);
        assert.equal(native.filter(({ danger }) => danger).length, 1);
      }
    }
  }
  const failure = profileMenuItems(actions, { sourceError: "source read failed" }, options(true));
  assert.equal(failure.find(({ id }) => id === "update").reason, "Subscription URL could not be read: source read failed");
});

function transport() {
  const calls = [], channels = [], results = [], failures = [];
  let presentReply = Promise.resolve();
  const menu = createNativeProfileMenu({
    invoke: (command, args) => { calls.push({ command, args }); return command === "present_native_profile_menu" ? presentReply : Promise.resolve(true); },
    makeChannel: (handler) => { const c = { receive: handler }; channels.push(c); return c; },
    onError: (error) => failures.push(error),
  });
  return { menu, calls, channels, results, failures, setPresent: (reply) => { presentReply = reply; } };
}
const request = (requestId, revision = 1) => ({ requestId, revision });

test("old native sessions and duplicate callbacks cannot execute an action twice", async () => {
  const h = transport();
  await h.menu.present(request("old"), (r) => h.results.push(r));
  await h.menu.present(request("new"), (r) => h.results.push(r));
  h.channels[0].receive({ requestId: "old", action: "delete", error: null });
  assert.deepEqual(h.results, [{ requestId: "old", action: null, error: null }]);
  h.channels[1].receive({ requestId: "new", action: "edit", error: null });
  h.channels[1].receive({ requestId: "new", action: "delete", error: null });
  assert.deepEqual(h.results.map((r) => r.action), [null, "edit"]);
  assert.equal(await h.menu.update(request("new", 2)), false);
});

test("metadata updates wait for accepted presentation and never go backwards", async () => {
  const h = transport();
  let admit;
  h.setPresent(new Promise((resolve) => { admit = resolve; }));
  const showing = h.menu.present(request("one"), (r) => h.results.push(r));
  assert.equal(await h.menu.update(request("one", 2)), false);
  admit(); await showing;
  assert.equal(await h.menu.update(request("one", 3)), true);
  assert.equal(await h.menu.update(request("one", 2)), false);
  assert.equal(await h.menu.update(request("other", 4)), false);
  await h.menu.dismiss();
  assert.equal(h.calls.at(-1).command, "dismiss_native_profile_menu");
  assert.equal(h.calls.at(-1).args.requestId, "one");
  h.channels[0].receive({ requestId: "one", action: null, error: null });
  assert.equal(h.results.length, 1);
});

test("presentation rejection and malformed callback remain explicit failures", async () => {
  const rejected = transport();
  rejected.setPresent(Promise.reject(new Error("parent window unavailable")));
  await assert.rejects(rejected.menu.present(request("one"), () => {}), /parent window unavailable/u);
  assert.equal(await rejected.menu.update(request("one", 2)), false);
  const h = transport();
  await h.menu.present(request("one"), (r) => h.results.push(r));
  h.channels[0].receive({ requestId: "wrong", action: "delete", error: null });
  assert.equal(h.results.length, 1);
  assert.equal(h.results[0].action, null);
  assert.match(h.results[0].error, /invalid result/u);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.calls.at(-1).command, "dismiss_native_profile_menu");
});

test("cancelling a pending presentation prevents a late selection and closes after acknowledgement", async () => {
  const h = transport();
  let admit;
  h.setPresent(new Promise((resolve) => { admit = resolve; }));
  const showing = h.menu.present(request("one"), (r) => h.results.push(r));
  await Promise.resolve();
  assert.equal(h.calls[0].command, "present_native_profile_menu");
  const closing = h.menu.dismiss();
  h.channels[0].receive({ requestId: "one", action: "delete", error: null });
  assert.deepEqual(h.results, [{ requestId: "one", action: null, error: null }]);
  admit();
  assert.equal(await showing, false);
  await closing;
  assert.deepEqual(h.calls.map(({ command }) => command), ["present_native_profile_menu", "dismiss_native_profile_menu"]);
  assert.equal(h.calls[1].args.requestId, "one");
});

test("a queued obsolete menu allocates no channel and cannot replace the latest menu", async () => {
  const h = transport();
  const old = h.menu.present(request("old"), (r) => h.results.push(r));
  const current = h.menu.present(request("new"), (r) => h.results.push(r));
  assert.equal(await old, false);
  assert.equal(await current, true);
  assert.equal(h.channels.length, 1);
  assert.deepEqual(h.calls.map(({ args }) => args.request.requestId), ["new"]);
  h.channels[0].receive({ requestId: "new", action: "edit", error: null });
  assert.deepEqual(h.results.map(({ action }) => action), [null, "edit"]);
});

test("replacing a pending menu serializes its close before the next presentation", async () => {
  const h = transport();
  let admit;
  h.setPresent(new Promise((resolve) => { admit = resolve; }));
  const old = h.menu.present(request("old"), (r) => h.results.push(r));
  await Promise.resolve();
  h.setPresent(Promise.resolve());
  const current = h.menu.present(request("new"), (r) => h.results.push(r));
  assert.equal(h.calls.length, 1);
  admit();
  assert.equal(await old, false);
  assert.equal(await current, true);
  assert.deepEqual(h.calls.map(({ command }) => command), ["present_native_profile_menu", "dismiss_native_profile_menu", "present_native_profile_menu"]);
  assert.equal(h.calls[1].args.requestId, "old");
  assert.equal(h.calls[2].args.request.requestId, "new");
});
