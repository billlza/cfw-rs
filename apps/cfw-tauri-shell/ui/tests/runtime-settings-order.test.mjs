// What the page takes from the answers about the runtime settings. An action
// goes on with its own read, or ends with that read's failure; where the
// page's hold ends one is in runtime-settings-press-order.test.mjs. The
// page, whether a refresh or an action asked:
// - takes a snapshot only while it answers the last thing the page asked. It
//   asks again because something may have changed, the selected profile for
//   one, and a write counts as asked when it ends, so an earlier snapshot may
//   be from before a change;
// - takes a failure unless the answer to something it asked later is already
//   in. A failure has no values that could be out of date, and it holds the
//   controls until the page shows settings again. Settings that were read
//   are such an answer whether or not the page shows them, but they end no
//   hold unless they are shown.
import test from "node:test";
import assert from "node:assert/strict";
import { createRuntimeSettingsUI } from "../src/runtime-settings.js";

const IN_FORCE = Object.freeze({ in_force: true, saved_ipv6_dns_enabled: true });

// A snapshot as the host serializes it: a switch that rests off is stored
// only while it is on. `effective` changes what is in force without a write,
// as a profile does for the IPv6 DNS setting it hands down.
function snapshot(revision, on = {}, effective = {}) {
  return {
    tunnel_mtu_limits: { minimum: 1280, maximum: 1500 },
    revision, in_force: true, saved_ipv6_dns_enabled: on.ipv6_dns_enabled ?? effective.ipv6_dns_enabled ?? true,
    settings: { preferred_mixed_port: null, log_level: "info", tunnel_mtu: 1500, allow_lan: false, lan_proxy: null, ...on },
    effective: { mixed_port: 7890, log_level: "info", tunnel_mtu: 1500, ipv6_dns_enabled: true, lan_proxy: null,
      mainland_china_direct: false, dns_leak_protection: false, webrtc_leak_protection: false, tcp_concurrency: true,
      ...on, ...effective },
  };
}

// A page whose host answers when the test says so. `calls` lists what the
// page asked, in order; each call is answered or refused by the test.
function page() {
  const state = { toggles: {}, engineMutationBusy: false, migrationHandoff: false };
  const calls = [];
  let refreshed = null;
  const ui = createRuntimeSettingsUI({
    state,
    invoke: (command, args) => new Promise((answer, reject) => {
      calls.push({ command, args, answer, refuse: (message) => reject(new Error(message)) });
    }),
    appendLog() {},
    renderPage() {},
    refreshRuntime: () => refreshed,
    dismissOtherDialogs() {},
  });
  // The page stays busy after a write until the returned function is called.
  const holdRefresh = () => {
    let finish;
    refreshed = new Promise((resolve) => { finish = resolve; });
    return finish;
  };
  return { state, ui, calls, holdRefresh };
}

// Every answer that was ready has been taken after one turn of the event loop.
const turn = () => new Promise((resolve) => setImmediate(resolve));

// What something the page does came to, for a test to await. The host of
// these tests answers only when a test says so, so a page that asked for more
// than the test answered would wait for good, and the test with it: Node does
// not end a test that awaits. An outcome that is not there after a few turns
// of the event loop never comes, and the test fails in place.
async function done(pending) {
  let outcome = null;
  pending.then((value) => { outcome = { value }; }, (error) => { outcome = { error }; });
  for (let turns = 0; outcome === null && turns < 3; turns += 1) await turn();
  assert.notEqual(outcome, null, "the page still waits for an answer that no test gave");
  if ("error" in outcome) throw outcome.error;
  return outcome.value;
}
const READ = "read_runtime_settings_snapshot";
const WRITE = "write_runtime_settings_snapshot";
const dnsOn = { dns_leak_protection: true };
const broken = () => ({ ...snapshot("broken"), tunnel_mtu_limits: null });

// In each of the first tests two switches are clicked one after the other.
// The first click's read, `calls[0]`, is answered last.

test("settings a switch read before another switch was saved do not replace what the save returned", async () => {
  const { state, ui, calls, holdRefresh } = page();
  const finishRefresh = holdRefresh();
  const first = ui.toggleMainlandChinaDirect(true);
  const second = ui.toggleDnsLeakProtection(true);
  calls[1].answer(snapshot("before"));
  await turn();
  assert.deepEqual(calls.map((call) => call.command), [READ, READ, WRITE]);
  assert.deepEqual(calls[2].args, { settings: snapshot("before", dnsOn).settings, revision: "before", basis: IN_FORCE });
  calls[2].answer(snapshot("after", dnsOn));
  await turn();
  assert.equal(state.runtimeSettings.revision, "after");
  assert.equal(state.engineMutationBusy, true);
  // The first read is answered only now, with the settings from before the save.
  calls[0].answer(snapshot("before"));
  await assert.rejects(done(first), /operation is in progress/u);
  assert.equal(state.runtimeSettings.revision, "after", "the page keeps what the save returned");
  assert.equal(state.toggles.dnsLeakProtection, true);
  assert.equal(state.runtimeSettingsError, null);
  finishRefresh();
  assert.equal(await done(second), true);
  assert.equal(calls.length, 3);
});

test("settings a switch read while a save failed do not replace the ones read after that save", async () => {
  const { state, ui, calls, holdRefresh } = page();
  const finishRefresh = holdRefresh();
  const first = ui.toggleMainlandChinaDirect(true);
  const second = ui.toggleDnsLeakProtection(true);
  calls[1].answer(snapshot("before"));
  await turn();
  calls[2].refuse("the new core did not start");
  await turn();
  // After a write that failed the page reads the settings again.
  assert.deepEqual(calls.map((call) => call.command), [READ, READ, WRITE, READ]);
  calls[3].answer(snapshot("restored"));
  await turn();
  assert.equal(state.runtimeSettings.revision, "restored");
  // The first read saw what the write had stored before it was taken back.
  calls[0].answer(snapshot("stored for a moment", dnsOn));
  await assert.rejects(done(first), /operation is in progress/u);
  assert.equal(state.runtimeSettings.revision, "restored", "the page keeps what it read after the save failed");
  assert.equal(state.toggles.dnsLeakProtection, false);
  finishRefresh();
  assert.equal(await done(second), false);
  assert.equal(calls.length, 4);
});

test("settings a switch read are not shown over newer ones while another switch is being saved", async () => {
  const { state, ui, calls } = page();
  const first = ui.toggleMainlandChinaDirect(true);
  const second = ui.toggleDnsLeakProtection(true);
  // The second click read later: the profile had turned IPv6 DNS on by then.
  calls[1].answer(snapshot("stored", {}, { ipv6_dns_enabled: true }));
  await turn();
  assert.deepEqual(calls.map((call) => call.command), [READ, READ, WRITE]);
  assert.equal(state.toggles.ipv6DNS, true);
  // The first read is answered while that write is under way.
  calls[0].answer(snapshot("stored", {}, { ipv6_dns_enabled: false }));
  await assert.rejects(done(first), /operation is in progress/u);
  assert.equal(state.toggles.ipv6DNS, true, "the page keeps the settings it asked for last");
  calls[2].answer(snapshot("after", dnsOn, { ipv6_dns_enabled: true }));
  assert.equal(await done(second), true);
  assert.equal(state.toggles.ipv6DNS, true);
  assert.equal(calls.length, 3);
});

test("a read that fails after another switch was saved does not take the saved settings from the page", async () => {
  const { state, ui, calls } = page();
  const first = ui.toggleMainlandChinaDirect(true);
  const second = ui.toggleDnsLeakProtection(true);
  calls[1].answer(snapshot("before"));
  await turn();
  calls[2].answer(snapshot("after", dnsOn));
  assert.equal(await done(second), true);
  // The first read is refused only now. Its click says so; the page has the
  // answer of a write that ended since.
  calls[0].refuse("settings store is locked");
  await assert.rejects(done(first), /settings store is locked/u);
  assert.equal(state.runtimeSettingsError, null, "the page still knows what the save returned");
  assert.equal(state.runtimeSettings.revision, "after");
  assert.equal(state.toggles.dnsLeakProtection, true);
  assert.equal(calls.length, 3);
});

test("settings the page does not take are still checked before the action uses them", async () => {
  const { state, ui, calls } = page();
  const first = ui.toggleMainlandChinaDirect(true);
  const second = ui.toggleDnsLeakProtection(true);
  calls[1].answer(snapshot("before"));
  await turn();
  calls[2].answer(snapshot("after", dnsOn));
  assert.equal(await done(second), true);
  assert.equal(state.engineMutationBusy, false);
  // No write is under way any more, so nothing but the check stops this one.
  calls[0].answer(broken());
  await assert.rejects(done(first), /MTU limits are invalid/u);
  assert.equal(calls.length, 3, "nothing was written from an answer that is no settings");
  assert.equal(state.runtimeSettings.revision, "after");
  assert.equal(state.runtimeSettingsError, null);
});

test("a write from settings that a save overtook is left to the backend, which refuses their revision", async () => {
  const { state, ui, calls } = page();
  const first = ui.toggleMainlandChinaDirect(true);
  const second = ui.toggleDnsLeakProtection(true);
  calls[1].answer(snapshot("before"));
  await turn();
  calls[2].answer(snapshot("after", dnsOn));
  assert.equal(await done(second), true);
  calls[0].answer(snapshot("before"));
  await turn();
  assert.equal(state.runtimeSettings.revision, "after", "the page does not go back while the write is on its way");
  assert.deepEqual(calls[3].args, { settings: { ...snapshot("before").settings, mainland_china_direct: true }, revision: "before", basis: IN_FORCE });
  calls[3].refuse("runtime settings changed while the update was prepared");
  await turn();
  calls[4].answer(snapshot("after", dnsOn));
  assert.equal(await done(first), false);
  assert.deepEqual(calls.map((call) => call.command), [READ, READ, WRITE, WRITE, READ]);
  assert.equal(state.runtimeSettings.revision, "after");
  assert.equal(state.toggles.dnsLeakProtection, true);
  assert.equal(state.toggles.mainlandChinaDirect, false);
});

test("a click reports the failure of its own read, whatever the page has read since", async () => {
  const { state, ui, calls } = page();
  const click = ui.toggleDnsLeakProtection(true);
  // The host announces a change and the page reads again. That read is
  // answered before the click's read is refused.
  const refresh = ui.load();
  calls[1].answer(snapshot("refreshed"));
  assert.equal(await done(refresh), true);
  calls[0].refuse("settings store is locked");
  await assert.rejects(done(click), /settings store is locked/u);
  assert.equal(state.runtimeSettingsError, null, "the page asked again after the click and was answered");
  assert.equal(state.runtimeSettings.revision, "refreshed");
  assert.equal(calls.length, 2);
});

test("a refresh asked while a save was under way changes nothing once the save has returned", async () => {
  for (const late of ["a snapshot", "a refusal"]) {
    const { state, ui, calls } = page();
    const click = ui.toggleDnsLeakProtection(true);
    calls[0].answer(snapshot("before"));
    await turn();
    assert.deepEqual(calls.map((call) => call.command), [READ, WRITE], late);
    // The host announces a change while the write is under way, and the page
    // reads again. That read is answered after the write, from before it.
    const refresh = ui.load();
    calls[1].answer(snapshot("after", dnsOn));
    assert.equal(await done(click), true, late);
    if (late === "a snapshot") calls[2].answer(snapshot("before"));
    else calls[2].refuse("settings store is locked");
    assert.equal(await done(refresh), false, late);
    assert.equal(state.runtimeSettings.revision, "after", late);
    assert.equal(state.toggles.dnsLeakProtection, true, late);
    assert.equal(state.runtimeSettingsError, null, late);
  }
});

test("settings a refresh read during a save that failed are not shown once the save has failed", async () => {
  const { state, ui, calls } = page();
  const click = ui.toggleDnsLeakProtection(true);
  calls[0].answer(snapshot("before"));
  await turn();
  assert.deepEqual(calls.map((call) => call.command), [READ, WRITE]);
  // The host announces a change while the write is under way, and the page
  // reads again. That read sees what the write stored before it was taken back.
  const refresh = ui.load();
  calls[1].refuse("the new core did not start");
  await turn();
  // After a write that failed the page reads the settings again.
  assert.deepEqual(calls.map((call) => call.command), [READ, WRITE, READ, READ]);
  calls[2].answer(snapshot("stored for a moment", dnsOn));
  assert.equal(await done(refresh), false);
  assert.equal(state.runtimeSettings.revision, "before", "the page waits for the read it made after the save failed");
  assert.equal(state.toggles.dnsLeakProtection, false);
  calls[3].answer(snapshot("restored"));
  assert.equal(await done(click), false);
  assert.equal(state.runtimeSettings.revision, "restored");
  assert.equal(state.toggles.dnsLeakProtection, false);
});

// From here on an answer arrives while the answer to something the page
// asked later is still awaited. A failure counts until that answer arrives;
// a snapshot does not, because the later request may know of a change.

const ACTIONS = [
  ["opening the dialog", (ui) => ui.open(), false],
  ["a stored switch", (ui) => ui.toggleDnsLeakProtection(true), true],
  ["turning LAN sharing off", (ui) => ui.toggleLAN(false), true],
];

test("a read that fails is told to the page while the answer to a later read is awaited", async () => {
  for (const [name, act, rejects] of ACTIONS) {
    const { state, ui, calls } = page();
    const known = ui.load();
    calls[0].answer(snapshot("known"));
    assert.equal(await done(known), true, name);
    const action = act(ui);
    // The host announces a change and the page reads again.
    const refresh = ui.load();
    calls[1].refuse("settings store is locked");
    if (rejects) await assert.rejects(done(action), /settings store is locked/u, name);
    else await done(action);
    assert.equal(state.runtimeSettingsDialog, undefined, name);
    assert.equal(state.runtimeSettingsError, "settings store is locked", `${name}: the page no longer knows the settings it shows`);
    calls[2].answer(snapshot("refreshed"));
    assert.equal(await done(refresh), true, name);
    assert.equal(state.runtimeSettingsError, null, name);
    assert.equal(state.runtimeSettings.revision, "refreshed", name);
    assert.equal(calls.length, 3, `${name}: nothing was written`);
  }
});

test("settings an action read are not shown while the answer to a later read is awaited", async () => {
  const { state, ui, calls } = page();
  const known = ui.load();
  calls[0].answer(snapshot("known"));
  assert.equal(await done(known), true);
  const click = ui.toggleDnsLeakProtection(true);
  // The page asks again, as it does when the host announces a change.
  const refresh = ui.load();
  calls[1].answer(snapshot("read for the click", {}, { ipv6_dns_enabled: false }));
  await turn();
  assert.equal(state.runtimeSettings.revision, "known", "the page waits for the read it asked for last");
  assert.equal(state.toggles.ipv6DNS, true);
  // The click goes on with what it read.
  assert.deepEqual(calls.map((call) => call.command), [READ, READ, READ, WRITE]);
  assert.deepEqual(calls[3].args, { settings: snapshot("read for the click", dnsOn).settings, revision: "read for the click", basis: { ...IN_FORCE, saved_ipv6_dns_enabled: false } });
  calls[2].answer(snapshot("refreshed"));
  assert.equal(await done(refresh), true);
  assert.equal(state.runtimeSettings.revision, "refreshed");
  calls[3].answer(snapshot("after", dnsOn));
  assert.equal(await done(click), true);
  assert.equal(state.runtimeSettings.revision, "after");
  assert.equal(state.toggles.dnsLeakProtection, true);
});

// The first refresh was asked while one profile was selected, the second
// after the selection changed. What the settings come to depends on the
// profile, so the first snapshot is no longer what is in force.
test("a refresh that a later one overtook: its snapshot counts for nothing, its failure until the later answer", async () => {
  for (const early of ["a snapshot", "a refusal"]) {
    const { state, ui, calls } = page();
    const known = ui.load();
    calls[0].answer(snapshot("known"));
    assert.equal(await done(known), true, early);
    const first = ui.load();
    const second = ui.load();
    if (early === "a snapshot") calls[1].answer(snapshot("of the profile before", {}, { ipv6_dns_enabled: false }));
    else calls[1].refuse("settings store is locked");
    assert.equal(await done(first), false, early);
    assert.equal(state.runtimeSettings.revision, "known", early);
    assert.equal(state.toggles.ipv6DNS, true, early);
    assert.equal(state.runtimeSettingsError, early === "a snapshot" ? null : "settings store is locked", early);
    calls[2].answer(snapshot("of the profile now"));
    assert.equal(await done(second), true, early);
    assert.equal(state.runtimeSettings.revision, "of the profile now", early);
    assert.equal(state.runtimeSettingsError, null, early);
  }
});

test("a refresh that is answered after a later one changes nothing on the page", async () => {
  for (const later of ["a snapshot", "a refusal"]) {
    for (const late of ["a snapshot", "a refusal"]) {
      const order = `${later}, then ${late}`;
      const { state, ui, calls } = page();
      const first = ui.load();
      const second = ui.load();
      if (later === "a snapshot") calls[1].answer(snapshot("second"));
      else calls[1].refuse("the later read failed");
      assert.equal(await done(second), later === "a snapshot", order);
      if (late === "a snapshot") calls[0].answer(snapshot("first"));
      else calls[0].refuse("the earlier read failed");
      assert.equal(await done(first), false, order);
      assert.equal(state.runtimeSettings?.revision, later === "a snapshot" ? "second" : undefined, order);
      assert.equal(state.runtimeSettingsError ?? null, later === "a snapshot" ? null : "the later read failed", order);
    }
  }
});

test("an answer that is no settings is a failed read for the page", async () => {
  const { state, ui, calls } = page();
  const refresh = ui.load();
  calls[0].answer(broken());
  assert.equal(await done(refresh), false);
  assert.match(state.runtimeSettingsError, /MTU limits are invalid/u);
  const again = ui.load();
  calls[1].answer(snapshot("read"));
  assert.equal(await done(again), true);
  assert.equal(state.runtimeSettingsError, null);
  const click = ui.toggleDnsLeakProtection(true);
  calls[2].answer(broken());
  await assert.rejects(done(click), /MTU limits are invalid/u);
  assert.match(state.runtimeSettingsError, /MTU limits are invalid/u, "the click's read is the last word on the settings");
  assert.equal(state.runtimeSettings.revision, "read");
  assert.equal(calls.length, 3, "nothing was written from an answer that is no settings");
});

test("an answer that is no settings is a failed read also when the page has asked again", async () => {
  const EARLIER = [
    ["a refresh", (ui) => ui.load()],
    ["an action", (ui) => ui.toggleMainlandChinaDirect(true)],
  ];
  for (const [name, ask] of EARLIER) {
    const { state, ui, calls } = page();
    const known = ui.load();
    calls[0].answer(snapshot("known"));
    assert.equal(await done(known), true, name);
    // The earlier read is on its way when a switch is clicked.
    const earlier = ask(ui);
    const click = ui.toggleDnsLeakProtection(true);
    calls[1].answer(broken());
    if (name === "a refresh") assert.equal(await done(earlier), false, name);
    else await assert.rejects(done(earlier), /MTU limits are invalid/u, name);
    assert.match(String(state.runtimeSettingsError), /MTU limits are invalid/u, `${name}: the page no longer knows the settings it shows`);
    assert.equal(state.runtimeSettings.revision, "known", name);
    // The click's read is answered: the page knows the settings again.
    calls[2].answer(snapshot("read for the click"));
    await turn();
    assert.equal(state.runtimeSettingsError, null, name);
    assert.equal(state.runtimeSettings.revision, "read for the click", name);
    assert.deepEqual(calls.map((call) => call.command), [READ, READ, READ, WRITE], name);
    calls[3].answer(snapshot("after", dnsOn));
    assert.equal(await done(click), true, name);
  }
});

test("an answer that is no settings changes nothing once the page has the answer to something it asked later", async () => {
  const { state, ui, calls } = page();
  const refresh = ui.load();
  const later = ui.load();
  calls[1].answer(snapshot("later"));
  assert.equal(await done(later), true);
  calls[0].answer(broken());
  assert.equal(await done(refresh), false);
  assert.equal(state.runtimeSettingsError, null);
  assert.equal(state.runtimeSettings.revision, "later");
});

// Three things asked. The second is answered with settings the page does not
// show, because it has asked again since. They were read all the same, so a
// failure of the first read that arrives after them is behind the page. A
// failure that arrives before them counted when it came, and its hold lasts
// until settings are shown: what would be on the page again otherwise is what
// was there before the failure, which the page had reason to doubt.
test("settings the page does not show put a later failure of an earlier read behind it, and end no hold", async () => {
  const EARLIEST = [
    ["a refresh", (ui) => ui.load()],
    ["a switch", (ui) => ui.toggleMainlandChinaDirect(true)],
  ];
  const MIDDLE = [
    ["a refresh", (ui) => ui.load()],
    ["the dialog", (ui) => ui.open()],
  ];
  for (const [earliest, askEarliest] of EARLIEST) {
    for (const [middle, askMiddle] of MIDDLE) {
      for (const first of ["the failure", "the settings"]) {
        const order = `${earliest} fails, ${middle} reads, ${first} first`;
        const { state, ui, calls } = page();
        const known = ui.load();
        calls[0].answer(snapshot("known"));
        assert.equal(await done(known), true, order);
        const failing = askEarliest(ui);
        const reading = askMiddle(ui);
        const last = ui.load();
        const fail = async () => {
          calls[1].refuse("settings store is locked");
          if (earliest === "a refresh") assert.equal(await done(failing), false, order);
          else await assert.rejects(done(failing), /settings store is locked/u, order);
        };
        const read = async () => {
          calls[2].answer(snapshot("not shown", {}, { ipv6_dns_enabled: false }));
          await done(reading);
        };
        if (first === "the failure") {
          await fail();
          assert.equal(state.runtimeSettingsError, "settings store is locked", `${order}: held when the failure arrives`);
          await read();
          assert.equal(state.runtimeSettingsError, "settings store is locked", `${order}: held until settings are shown`);
        } else {
          await read();
          await fail();
          assert.equal(state.runtimeSettingsError, null, `${order}: the failed read is behind the page`);
        }
        assert.equal(state.runtimeSettings.revision, "known", `${order}: the page waits for the read it asked for last`);
        assert.equal(state.toggles.ipv6DNS, true, order);
        if (middle === "the dialog") assert.equal(state.runtimeSettingsDialog.revision, "not shown", order);
        calls[3].answer(snapshot("last"));
        assert.equal(await done(last), true, order);
        assert.equal(state.runtimeSettings.revision, "last", order);
        assert.equal(state.runtimeSettingsError, null, order);
        assert.equal(calls.length, 4, order);
      }
    }
  }
});

// The read fails while it is the last thing the page asked, and the page
// asks twice more. The first of the two answers is not shown and ends no
// hold; the second does when it brings settings.
test("a failed read holds the controls until the page shows settings again", async () => {
  for (const before of ["known settings", "no settings"]) {
    const { state, ui, calls } = page();
    if (before === "known settings") {
      const known = ui.load();
      calls[0].answer(snapshot("known"));
      assert.equal(await done(known), true, before);
    }
    const base = calls.length;
    const failing = ui.load();
    calls[base].refuse("settings store is locked");
    assert.equal(await done(failing), false, before);
    assert.equal(state.runtimeSettingsError, "settings store is locked", before);
    const middle = ui.load();
    const last = ui.load();
    calls[base + 1].answer(snapshot("not shown", {}, { ipv6_dns_enabled: false }));
    assert.equal(await done(middle), false, before);
    assert.equal(state.runtimeSettingsError, "settings store is locked", `${before}: settings that are not shown end no hold`);
    assert.equal(state.runtimeSettings?.revision, before === "known settings" ? "known" : undefined, before);
    calls[base + 2].answer(snapshot("last"));
    assert.equal(await done(last), true, before);
    assert.equal(state.runtimeSettingsError, null, before);
    assert.equal(state.runtimeSettings.revision, "last", before);
  }
});

// Why settings that are not shown end no hold. A refresh during a write reads
// the settings the host has stored for the core it is starting. The core does
// not start, the host takes them back, and the read after the failed write
// fails as well. The page then still has those settings, and only the hold
// keeps it from showing them as what is in force.
test("settings that a failed write did not keep stay held when a read the page does not show is answered", async () => {
  const { state, ui, calls } = page();
  const first = ui.load();
  calls[0].answer(snapshot("stored"));
  assert.equal(await done(first), true);
  const click = ui.toggleDnsLeakProtection(true);
  calls[1].answer(snapshot("stored"));
  await turn();
  assert.deepEqual(calls.map((call) => call.command), [READ, READ, WRITE]);
  const during = ui.load();
  calls[3].answer(snapshot("candidate", dnsOn));
  assert.equal(await done(during), true);
  calls[2].refuse("the new core did not start");
  await turn();
  calls[4].refuse("settings store is locked");
  assert.equal(await done(click), false);
  assert.equal(state.runtimeSettingsError, "settings store is locked");
  // The application reads again after the write, and once more for an event.
  const after = ui.load();
  const later = ui.load();
  calls[5].answer(snapshot("stored"));
  assert.equal(await done(after), false);
  assert.deepEqual([state.runtimeSettings.revision, state.toggles.dnsLeakProtection], ["candidate", true]);
  assert.equal(state.runtimeSettingsError, "settings store is locked", "what the page has is not what the host kept");
  calls[6].answer(snapshot("stored"));
  assert.equal(await done(later), true);
  assert.deepEqual([state.runtimeSettings.revision, state.toggles.dnsLeakProtection], ["stored", false]);
  assert.equal(state.runtimeSettingsError, null);
  assert.equal(calls.length, 7);
});
