// Background subscription updates in the dashboard: the host's report, the
// interval setting, the note beside a profile and applying a waiting change.
import { dom, element, host, settle, spy } from "./support/fake-host.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state } from "../src/state.js";
import {
  UPDATE_INTERVAL_OPTIONS, createSubscriptionUpdates, renderSubscriptionUpdateNote, subscriptionUpdatesFrom,
} from "../src/subscription-updates.js";

/// The log, oldest line first.
const logged = () => state.logs.map(({ level, source, message }) => [level, source, message]).reverse();
const report = (overrides = {}) => ({ interval: "daily", profiles: [], ...overrides });
const shown = () => ({
  interval: state.subscriptionUpdates.interval,
  notes: [...state.subscriptionUpdates.notes],
  error: state.subscriptionUpdates.error,
});

beforeEach(() => {
  host.reset();
  dom.reset();
  state.logs = [];
  state.migrationHandoff = false;
  state.profiles = [
    { id: "work", name: "Work", active: true, sourceKind: "subscription", updated: "now" },
    { id: "home", name: "Home", active: false, sourceKind: "subscription", updated: "now" },
  ];
  state.engine = { ...state.engine, active: true, state: "ProxyActive", desiredMode: "system_proxy" };
  state.subscriptionUpdates = { interval: "off", notes: new Map(), error: null, applying: new Set() };
});

function controller(overrides = {}) {
  const deps = {
    renderPage: spy(),
    loadProfilesSnapshot: spy(async () => true),
    loadRuntimeProjection: spy(async () => undefined),
    runProfileMenuAction: spy(async () => undefined),
    ...overrides,
  };
  return { deps, updates: createSubscriptionUpdates(deps) };
}

async function choose(updates, value) {
  const select = dom.setAll("[data-subscription-update-interval]", [element("select", { value })])[0];
  updates.bindPage();
  await select.fire("change");
}

function applyButton(updates, id) {
  const button = element("button");
  button.dataset.profileUpdate = id;
  dom.setAll("[data-profile-update]", [button]);
  updates.bindPage();
  return button;
}

test("the host's report is read whole or refused", () => {
  assert.deepEqual(
    subscriptionUpdatesFrom({
      interval: "weekly",
      profiles: [
        { id: "a", attempted_epoch_secs: 5, state: "waiting" },
        { id: "b", attempted_epoch_secs: 6, state: "failed", error: "timed out" },
      ],
    }),
    { interval: "weekly", notes: new Map([["a", { state: "waiting" }], ["b", { state: "failed", error: "timed out" }]]) },
  );
  assert.deepEqual(
    UPDATE_INTERVAL_OPTIONS.map(({ value }) => subscriptionUpdatesFrom({ interval: value, profiles: [] }).interval),
    ["off", "six_hours", "twelve_hours", "daily", "weekly"],
  );
  for (const malformed of [
    null,
    {},
    { interval: "hourly", profiles: [] },
    { interval: "daily" },
    { interval: "daily", profiles: {} },
    { interval: "daily", profiles: [null] },
    { interval: "daily", profiles: [{ state: "waiting" }] },
    { interval: "daily", profiles: [{ id: "", state: "waiting" }] },
    { interval: "daily", profiles: [{ id: "a", state: "updated" }] },
    { interval: "daily", profiles: [{ id: "a", state: "failed" }] },
    { interval: "daily", profiles: [{ id: "a", state: "failed", error: 5 }] },
  ]) {
    assert.throws(() => subscriptionUpdatesFrom(malformed), /^TypeError: subscription update report is malformed$/u, JSON.stringify(malformed));
  }
});

test("a failure's reason is kept without the credentials it may quote", () => {
  const { notes } = subscriptionUpdatesFrom(report({
    profiles: [{ id: "a", state: "failed", error: "refused https://example.test/sub?token=abc123" }],
  }));
  assert.deepEqual(notes.get("a"), { state: "failed", error: "refused https://example.test/sub?token=[redacted]" });
});

test("the interval and the notes are read from the host", async () => {
  const { updates } = controller();
  host.respond("subscription_updates", report({ profiles: [{ id: "work", attempted_epoch_secs: 5, state: "waiting" }] }));
  await updates.load();
  assert.deepEqual(shown(), { interval: "daily", notes: [["work", { state: "waiting" }]], error: null });
  assert.deepEqual(host.commands(), ["subscription_updates"]);
  assert.deepEqual(logged(), []);
});

test("a read the host refuses, or answers in another shape, is shown and logged until a read succeeds", async () => {
  const { updates } = controller();
  state.subscriptionUpdates.interval = "daily";
  state.subscriptionUpdates.notes.set("work", { state: "waiting" });
  host.respond("subscription_updates", new Error("the stored document is not canonical"));
  await updates.load();
  assert.deepEqual(shown(), { interval: "off", notes: [], error: "the stored document is not canonical" });

  host.respond("subscription_updates", { interval: "hourly", profiles: [] });
  await updates.load();
  assert.deepEqual(shown(), { interval: "off", notes: [], error: "subscription update report is malformed" });
  assert.deepEqual(logged(), [
    ["error", "settings", "Automatic subscription updates are unavailable: the stored document is not canonical"],
    ["error", "settings", "Automatic subscription updates are unavailable: subscription update report is malformed"],
  ]);

  host.respond("subscription_updates", report({ interval: "weekly" }));
  await updates.load();
  assert.deepEqual(shown(), { interval: "weekly", notes: [], error: null });
});

test("a read nobody waits for is rendered when it arrives, whatever it found", async () => {
  const { deps, updates } = controller();
  let answer;
  host.respond("subscription_updates", () => new Promise((resolve) => { answer = resolve; }));
  const reading = updates.loadAndRender();
  await settle();
  assert.equal(deps.renderPage.count(), 0, "nothing is rendered before the answer");
  answer(report({ interval: "weekly" }));
  await reading;
  assert.equal(shown().interval, "weekly");
  assert.equal(deps.renderPage.count(), 1);

  host.respond("subscription_updates", new Error("the stored document is not canonical"));
  await updates.loadAndRender();
  assert.equal(shown().error, "the stored document is not canonical");
  assert.equal(deps.renderPage.count(), 2, "a failed read is rendered too: it disables the setting");
});

test("the migration handoff window asks the host nothing", async () => {
  state.migrationHandoff = true;
  const { updates } = controller();
  await updates.load();
  assert.deepEqual(host.commands(), []);
  assert.deepEqual(shown(), { interval: "off", notes: [], error: null });
  assert.deepEqual(logged(), []);
});

test("choosing an interval stores it, takes the host's answer and says so", async () => {
  const { deps, updates } = controller();
  state.subscriptionUpdates.notes.set("work", { state: "waiting" });
  state.subscriptionUpdates.error = "an earlier read failed";
  host.respond("set_subscription_update_interval", ({ interval }) => report({ interval }));
  await choose(updates, "six_hours");
  assert.deepEqual(host.argsOf("set_subscription_update_interval"), [{ interval: "six_hours" }]);
  assert.deepEqual(shown(), { interval: "six_hours", notes: [], error: null });
  assert.deepEqual(logged(), [["info", "settings", "Automatic subscription updates: Every 6 hours"]]);
  assert.equal(deps.renderPage.count(), 1);

  // The log names the interval the host stored, not the one that was asked for.
  host.respond("set_subscription_update_interval", report({ interval: "off" }));
  await choose(updates, "weekly");
  assert.deepEqual(logged().at(-1), ["info", "settings", "Automatic subscription updates: Off"]);
});

test("a refused interval is reported and the stored one is read again", async () => {
  const { deps, updates } = controller();
  host.respond("set_subscription_update_interval", new Error("the settings changed elsewhere"));
  host.respond("subscription_updates", report({ interval: "weekly" }));
  await choose(updates, "daily");
  assert.deepEqual(host.commands(), ["set_subscription_update_interval", "subscription_updates"]);
  assert.deepEqual(shown(), { interval: "weekly", notes: [], error: null });
  assert.deepEqual(logged(), [["error", "settings", "Automatic subscription updates were not changed: the settings changed elsewhere"]]);
  assert.equal(deps.renderPage.count(), 1);
});

test("a report of a look replaces the notes and reloads the profiles it saved again", async () => {
  const { deps, updates } = controller();
  state.subscriptionUpdates.notes.set("home", { state: "failed", error: "timed out" });
  await updates.onChanged({
    payload: report({
      profiles: [{ id: "work", attempted_epoch_secs: 5, state: "waiting" }],
      updated: [
        { id: "home", name: "Home", reset_proxy_groups: [] },
        { id: "lab", name: "Lab", reset_proxy_groups: ["Auto", "Media"] },
      ],
    }),
  });
  assert.deepEqual(shown(), { interval: "daily", notes: [["work", { state: "waiting" }]], error: null });
  assert.deepEqual(logged(), [
    ["info", "profile", "Home updated automatically"],
    ["info", "profile", "Lab updated automatically"],
    ["warning", "profile", "Saved nodes were removed from these groups; the new defaults apply: Auto, Media"],
  ]);
  assert.equal(deps.loadProfilesSnapshot.count(), 1);
  assert.equal(deps.loadRuntimeProjection.count(), 1);
  assert.equal(deps.renderPage.count(), 1);
  assert.deepEqual(host.commands(), []);
});

test("a report that saved no profile again reloads nothing", async () => {
  const { deps, updates } = controller();
  state.subscriptionUpdates.notes.set("work", { state: "waiting" });
  await updates.onChanged({ payload: report({ updated: [] }) });
  assert.deepEqual(shown(), { interval: "daily", notes: [], error: null });
  assert.equal(deps.loadProfilesSnapshot.count(), 0);
  assert.equal(deps.loadRuntimeProjection.count(), 0);
  assert.equal(deps.renderPage.count(), 1);
  assert.deepEqual(logged(), []);
});

test("a malformed report changes nothing by itself: the host is asked for its state", async () => {
  for (const payload of [
    report(),
    report({ updated: [{ id: "home", name: "Home" }] }),
    report({ updated: [{ id: "home", name: "", reset_proxy_groups: [] }] }),
    report({ updated: [{ id: "", name: "Home", reset_proxy_groups: [] }] }),
    report({ updated: [{ id: "home", name: "Home", reset_proxy_groups: [5] }] }),
    { interval: "hourly", profiles: [], updated: [{ id: "home", name: "Home", reset_proxy_groups: [] }] },
  ]) {
    host.reset();
    state.logs = [];
    state.subscriptionUpdates.notes = new Map([["work", { state: "waiting" }]]);
    const { deps, updates } = controller();
    host.respond("subscription_updates", report({ interval: "weekly" }));
    await updates.onChanged({ payload });
    const name = JSON.stringify(payload);
    assert.deepEqual(host.commands(), ["subscription_updates"], name);
    assert.deepEqual(shown(), { interval: "weekly", notes: [], error: null }, name);
    assert.deepEqual(logged(), [
      ["error", "profile", "Rejected an invalid subscription update report: subscription update report is malformed"],
    ], name);
    assert.equal(deps.loadProfilesSnapshot.count(), 0, name);
    assert.equal(deps.renderPage.count(), 1, name);
  }
});

test("applying a waiting change runs the profile's update once and shows it running", async () => {
  let finish;
  const running = new Promise((resolve) => { finish = resolve; });
  const { deps, updates } = controller({ runProfileMenuAction: spy(() => running) });
  const waiting = ["work", "home"].map((id) => ({ id, attempted_epoch_secs: 5, state: "waiting" }));
  await updates.onChanged({ payload: report({ profiles: waiting, updated: [] }) });
  const [work, home] = state.profiles;
  const busy = 'data-profile-update="work" disabled>Applying…</button>';
  const button = applyButton(updates, "work");

  const first = button.fire("click");
  await settle();
  assert.equal(deps.renderPage.count(), 2, "the card is rendered as busy at once");
  assert.ok(renderSubscriptionUpdateNote(work).includes(busy));
  assert.ok(
    renderSubscriptionUpdateNote(home).includes('data-profile-update="home" >Apply update</button>'),
    "another profile's change is not shown as running",
  );
  // A report that arrives meanwhile leaves the running application running.
  await updates.onChanged({ payload: report({ profiles: waiting, updated: [] }) });
  assert.ok(renderSubscriptionUpdateNote(work).includes(busy));
  const second = button.fire("click");
  await settle();
  assert.deepEqual(deps.runProfileMenuAction.calls, [["update", "work"]], "a second click while it runs starts nothing");

  finish();
  await Promise.all([first, second]);
  assert.equal(state.subscriptionUpdates.applying.size, 0);
  assert.equal(deps.renderPage.count(), 4);
  assert.ok(renderSubscriptionUpdateNote(work).includes('data-profile-update="work" >Apply update</button>'));
  assert.deepEqual(logged(), []);

  await button.fire("click");
  assert.equal(deps.runProfileMenuAction.count(), 2, "it can be applied again once the first attempt ended");
});

test("an update that fails is reported and the change keeps waiting", async () => {
  const { deps, updates } = controller({
    runProfileMenuAction: spy(async () => { throw new Error("subscription request timed out"); }),
  });
  state.subscriptionUpdates.notes.set("work", { state: "waiting" });
  await applyButton(updates, "work").fire("click");
  assert.deepEqual(logged(), [["error", "profile", "Update failed: subscription request timed out"]]);
  assert.equal(state.subscriptionUpdates.applying.size, 0);
  assert.deepEqual(shown().notes, [["work", { state: "waiting" }]]);
  assert.equal(deps.renderPage.count(), 2);
});

test("a card shows nothing, a waiting change with what applying it does, or why an update failed", () => {
  const [work, home] = state.profiles;
  assert.equal(renderSubscriptionUpdateNote(work), "");

  state.subscriptionUpdates.notes = new Map([["work", { state: "waiting" }], ["home", { state: "waiting" }]]);
  const running = renderSubscriptionUpdateNote(work);
  assert.ok(running.includes('<p class="profile-card-update" role="note">New subscription content is available. Applying it restarts the core.</p>'));
  assert.ok(running.includes('<button class="profile-card-apply" data-profile-update="work" >Apply update</button>'));
  // Only the profile the core runs needs a restart.
  const plain = '<p class="profile-card-update" role="note">New subscription content is available.</p>';
  assert.ok(renderSubscriptionUpdateNote(home).includes(plain));
  state.engine = { ...state.engine, active: false, state: "Off", desiredMode: "off" };
  assert.ok(renderSubscriptionUpdateNote(work).includes(plain));

  state.subscriptionUpdates.notes = new Map([["work", { state: "failed", error: "<b>timed out</b>" }]]);
  assert.equal(
    renderSubscriptionUpdateNote(work),
    '<p class="profile-card-update failed" role="note">Automatic update failed: &lt;b&gt;timed out&lt;/b&gt;</p>',
  );

  const hostile = { id: 'a"><script>', name: "x", active: false };
  state.subscriptionUpdates.notes = new Map([[hostile.id, { state: "waiting" }]]);
  assert.ok(renderSubscriptionUpdateNote(hostile).includes('data-profile-update="a&quot;&gt;&lt;script&gt;" >'));
});
