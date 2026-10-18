// The page's side of the native window glass: what it measures, when it
// presents, updates and dismisses, and that its glass class follows the host.
import assert from "node:assert/strict";
import nodeTest from "node:test";
import { GLASS_CLASS, GLASS_REGIONS, createWindowGlass, measureGlassFrame } from "../src/window-glass.js";

const test = (name, fn) => nodeTest(name, { timeout: 5000 }, fn);

function fakeDocument(rects, theme = "light") {
  const classes = new Set();
  return {
    documentElement: {
      dataset: { theme },
      classList: {
        toggle: (name, active) => { if (active) classes.add(name); else classes.delete(name); },
        contains: (name) => classes.has(name),
      },
    },
    querySelector: (selector) => {
      const rect = rects[selector];
      if (!rect) return null;
      return { getBoundingClientRect: () => ({ left: rect[0], top: rect[1], width: rect[2], height: rect[3] }) };
    },
  };
}

const LAYOUT = {
  ".status-bar": [0, 0, 1120, 36],
  ".sidebar": [14, 36, 196, 670],
  ".traffic-pane": [24, 46, 176, 84],
  ".nav-item.active": [24, 140, 176, 44],
  ".runtime-pane": [24, 560, 176, 60],
  ".sidebar-meta": [24, 630, 176, 60],
  ".workspace": [224, 36, 882, 670],
};

function harness({ rects = LAYOUT, theme = "light", enabled = true, answers = {} } = {}) {
  const doc = fakeDocument(rects, theme);
  const win = { innerWidth: 1120, innerHeight: 720 };
  const calls = [];
  const channels = [];
  const errors = [];
  let ids = 0;
  const glass = createWindowGlass({
    invoke: async (command, args) => {
      calls.push({ command, args });
      const answer = answers[command];
      if (answer instanceof Error) throw answer;
      return typeof answer === "function" ? answer(args) : answer;
    },
    makeChannel: (handler) => { const channel = { handler }; channels.push(channel); return channel; },
    enabled: () => enabled,
    doc, win, randomUUID: () => `id-${++ids}`,
    onError: (error) => errors.push(error),
  });
  return { glass, doc, win, calls, channels, errors };
}

test("the frame names every region in page order with its kind and radius", () => {
  const frame = measureGlassFrame(fakeDocument(LAYOUT), { innerWidth: 1120, innerHeight: 720 }, "dark");
  assert.deepEqual(frame.viewport, { width: 1120, height: 720 });
  assert.equal(frame.appearance, "dark");
  assert.deepEqual(frame.panels.map((panel) => panel.id), GLASS_REGIONS.map((region) => region.id));
  assert.deepEqual(frame.panels[3], { id: "nav-active", kind: "pill", x: 24, y: 140, width: 176, height: 44, radius: 0 });
  assert.deepEqual(frame.panels[1], { id: "sidebar", kind: "panel", x: 14, y: 36, width: 196, height: 670, radius: 22 });
  assert.equal(GLASS_REGIONS.length <= 32, true);
  assert.equal(new Set(GLASS_REGIONS.map((region) => region.id)).size, GLASS_REGIONS.length);
});

test("a region that is absent is left out and a page without regions or viewport has no frame", () => {
  const partial = measureGlassFrame(fakeDocument({ ".workspace": [0, 0, 10, 10] }), { innerWidth: 500, innerHeight: 400 }, "light");
  assert.deepEqual(partial.panels.map((panel) => panel.id), ["workspace"]);
  assert.equal(measureGlassFrame(fakeDocument({}), { innerWidth: 500, innerHeight: 400 }, "light"), null);
  assert.equal(measureGlassFrame(fakeDocument(LAYOUT), { innerWidth: 0, innerHeight: 400 }, "light"), null);
  assert.equal(measureGlassFrame(fakeDocument(LAYOUT), { innerWidth: Number.NaN, innerHeight: 400 }, "light"), null);
  const negative = measureGlassFrame(fakeDocument({ ".sidebar": [0, 0, -5, 10] }), { innerWidth: 500, innerHeight: 400 }, "light");
  assert.deepEqual([negative.panels[0].width, negative.panels[0].height], [0, 10]);
  assert.equal(measureGlassFrame(fakeDocument({ ".sidebar": [Number.NaN, 0, 5, 10] }), { innerWidth: 500, innerHeight: 400 }, "light"), null);
});

test("the first refresh presents, a changed layout updates with the next sequence and an unchanged one is silent", async () => {
  const { glass, doc, calls, win } = harness({ answers: { present_native_window_glass: null, update_native_window_glass: true } });
  assert.equal(glass.active(), false);
  await glass.refresh();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "present_native_window_glass");
  assert.equal(calls[0].args.request.requestId, "id-1");
  assert.equal(calls[0].args.request.sequence, 1);
  assert.equal(calls[0].args.request.acknowledgedSubmission, 0);
  assert.equal(calls[0].args.request.appearance, "light");
  assert.equal(calls[0].args.request.panels.length, 7);
  assert.equal(doc.documentElement.classList.contains(GLASS_CLASS), true);
  assert.equal(glass.active(), true);

  await glass.refresh();
  assert.equal(calls.length, 1, "an unchanged layout sends nothing");

  win.innerWidth = 1200;
  await glass.refresh();
  assert.equal(calls.length, 2);
  assert.equal(calls[1].command, "update_native_window_glass");
  assert.deepEqual([calls[1].args.request.requestId, calls[1].args.request.sequence], ["id-1", 2]);
  assert.equal(calls[1].args.request.viewport.width, 1200);

  doc.documentElement.dataset.theme = "dark";
  await glass.refresh();
  assert.equal(calls[2].args.request.sequence, 3);
  assert.equal(calls[2].args.request.appearance, "dark");
  assert.equal(doc.documentElement.classList.contains(GLASS_CLASS), true);
});

test("a stale viewport answer keeps the session and the next render measures again", async () => {
  const { glass, calls, doc, win, errors } = harness({ answers: { present_native_window_glass: null, update_native_window_glass: false } });
  await glass.refresh();
  win.innerHeight = 800;
  await glass.refresh();
  assert.equal(calls[1].command, "update_native_window_glass");
  assert.equal(glass.active(), true);
  assert.equal(doc.documentElement.classList.contains(GLASS_CLASS), true);
  assert.deepEqual(errors, []);
  win.innerHeight = 810;
  await glass.refresh();
  assert.equal(calls[2].args.request.sequence, 3);
});

test("a refused present or update ends the session and takes the page's glass away", async () => {
  const refused = harness({ answers: { present_native_window_glass: new Error("no window") } });
  await refused.glass.refresh();
  assert.equal(refused.glass.active(), false);
  assert.equal(refused.doc.documentElement.classList.contains(GLASS_CLASS), false);
  assert.equal(refused.errors.length, 1);
  await refused.glass.refresh();
  assert.equal(refused.calls.length, 2, "the next render tries again");

  const failing = harness({ answers: { present_native_window_glass: null, update_native_window_glass: new Error("gone") } });
  await failing.glass.refresh();
  failing.win.innerWidth = 999;
  await failing.glass.refresh();
  assert.equal(failing.glass.active(), false);
  assert.equal(failing.doc.documentElement.classList.contains(GLASS_CLASS), false);
  assert.equal(failing.errors.length, 1);

  const invalid = harness({ answers: { present_native_window_glass: null, update_native_window_glass: "yes" } });
  await invalid.glass.refresh();
  invalid.win.innerWidth = 999;
  await invalid.glass.refresh();
  assert.equal(invalid.glass.active(), false);
  assert.match(invalid.errors[0].message, /invalid result/);
});

test("the host closing the glass removes the page's class and a later render presents anew", async () => {
  const { glass, doc, channels, calls } = harness({ answers: { present_native_window_glass: null } });
  await glass.refresh();
  channels[0].handler({ kind: "closed", requestId: "other" });
  assert.equal(glass.active(), true, "another request's close is not this session's");
  channels[0].handler({ kind: "closed", requestId: "id-1" });
  assert.equal(glass.active(), false);
  assert.equal(doc.documentElement.classList.contains(GLASS_CLASS), false);
  await glass.refresh();
  assert.equal(calls[1].command, "present_native_window_glass");
  assert.equal(calls[1].args.request.requestId, "id-2");
});

test("a session closed while the host answers the present never gets the glass class", async () => {
  const h = harness({
    answers: {
      present_native_window_glass: () => { h.channels[0].handler({ kind: "closed", requestId: "id-1" }); return null; },
    },
  });
  await h.glass.refresh();
  assert.equal(h.glass.active(), false);
  assert.equal(h.doc.documentElement.classList.contains(GLASS_CLASS), false);
  assert.deepEqual(h.errors, []);
});

test("disabling the glass or losing every region dismisses the session once", async () => {
  let on = true;
  const doc = fakeDocument(LAYOUT);
  const calls = [];
  const glass = createWindowGlass({
    invoke: async (command, args) => { calls.push(command); return command === "present_native_window_glass" ? null : true; },
    makeChannel: (handler) => ({ handler }), enabled: () => on,
    doc, win: { innerWidth: 900, innerHeight: 600 }, randomUUID: () => "id", onError: () => {},
  });
  await glass.refresh();
  on = false;
  await glass.refresh();
  assert.deepEqual(calls, ["present_native_window_glass", "dismiss_native_window_glass"]);
  assert.equal(doc.documentElement.classList.contains(GLASS_CLASS), false);
  await glass.refresh();
  assert.equal(calls.length, 2);
  on = true;
  await glass.refresh();
  assert.equal(calls.length, 3);
  doc.querySelector = () => null;
  await glass.refresh();
  assert.equal(calls[3], "dismiss_native_window_glass");
  await glass.stop();
  assert.equal(calls.length, 4, "nothing to dismiss twice");
});

test("overlapping refreshes are serialized and the newest layout wins", async () => {
  let resolvePresent;
  const { glass, calls, win } = harness({
    answers: {
      present_native_window_glass: () => new Promise((resolve) => { resolvePresent = resolve; }),
      update_native_window_glass: true,
    },
  });
  const first = glass.refresh();
  win.innerWidth = 1300;
  const second = glass.refresh();
  const third = glass.refresh();
  resolvePresent(null);
  await Promise.all([first, second, third]);
  assert.deepEqual(calls.map((call) => call.command), ["present_native_window_glass", "update_native_window_glass"]);
  assert.equal(calls[1].args.request.viewport.width, 1300);
});
