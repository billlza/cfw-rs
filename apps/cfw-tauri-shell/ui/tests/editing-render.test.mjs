import assert from "node:assert/strict";
import test from "node:test";
import { createEditingRender, createScrollKeeper } from "../src/editing-render.js";

function fixture() {
  const events = new Map();
  const frames = [];
  const root = { id: "page", fields: [], querySelectorAll() { return this.fields; } };
  const document = {
    activeElement: null,
    getElementById: (id) => id === root.id ? root : null,
    addEventListener: (name, callback) => events.set(name, callback),
  };
  const field = (attribute = 'filter["quoted"]', tag = "INPUT") => ({
    tagName: tag, type: "text", disabled: false,
    selectionStart: 2, selectionEnd: 4, selectionDirection: "backward",
    scrollTop: 12, scrollLeft: 8,
    closest: () => root, getAttributeNames: () => ["data-field", "value"],
    getAttribute: (name) => name === "data-field" ? attribute : "private form value",
    focus(options) { assert.equal(options.preventScroll, true); document.activeElement = this; },
    setSelectionRange(start, end, direction) { this.selection = [start, end, direction]; },
  });
  let renderCalls = 0;
  const editing = createEditingRender({ document,
    requestFrame: (callback) => frames.push(callback), rerender: () => { renderCalls += 1; } });
  editing.bind();
  editing.render(["proxies"], () => {});
  return { document, root, field, editing, events, frames, renders: () => renderCalls };
}

test("refresh restores the exact input, selection and scroll without retaining its value", () => {
  const f = fixture();
  f.document.activeElement = f.field();
  const next = f.field();
  f.editing.render(["proxies"], () => { f.root.fields = [next]; f.document.activeElement = null; });
  assert.equal(f.document.activeElement, next);
  assert.deepEqual(next.selection, [2, 4, "backward"]);
  assert.equal(next.scrollTop, 12);
  assert.equal(next.scrollLeft, 8);
});

test("navigation, changed dialogs and ambiguous fields do not steal focus", () => {
  for (const change of ["page", "dialog", "duplicate"]) {
    const f = fixture();
    f.document.activeElement = f.field();
    f.editing.render(change === "page" ? ["rules"] : change === "dialog" ? ["proxies", {}] : ["proxies"], () => {
      f.root.fields = change === "duplicate" ? [f.field(), f.field()] : [f.field()];
      f.document.activeElement = null;
    });
    assert.equal(f.document.activeElement, null, change);
  }
});

test("composition keeps its DOM alive and coalesces pending refreshes until commit", () => {
  const f = fixture();
  const editor = f.field("editor", "TEXTAREA");
  f.document.activeElement = editor;
  f.events.get("compositionstart")({ target: editor });
  let draws = 0;
  for (let i = 0; i < 10; i += 1) f.editing.render(["proxies"], () => { draws += 1; });
  assert.equal(draws, 0);
  assert.equal(f.document.activeElement, editor);
  f.events.get("compositionend")({ target: editor });
  assert.equal(f.frames.length, 1);
  assert.equal(f.renders(), 0);
  f.frames.shift()();
  assert.equal(f.renders(), 1);
  f.editing.render(["proxies"], () => { draws += 1; });
  assert.equal(draws, 1);
});

test("final input or deliberate navigation cancels a redundant composition redraw", () => {
  for (const context of [["proxies"], ["profiles"]]) {
    const f = fixture(); const editor = f.field(); f.document.activeElement = editor;
    f.events.get("compositionstart")({ target: editor });
    f.editing.render(["proxies"], () => assert.fail("composition must not be replaced"));
    f.events.get("compositionend")({ target: editor });
    let draws = 0;
    f.editing.render(context, () => { draws += 1; });
    f.frames.shift()();
    assert.equal(draws, 1);
    assert.equal(f.renders(), 0);
  }
});

test("render exceptions remain observable", () => {
  const f = fixture();
  assert.throws(() => f.editing.render(["proxies"], () => { throw new Error("render failed"); }), /render failed/u);
});

function region(tag, attributes) {
  const values = new Map(Object.entries(attributes));
  return { tagName: tag, scrollTop: 0, scrollLeft: 0,
    getAttributeNames: () => [...values.keys()], getAttribute: (name) => values.get(name) ?? null };
}

/// A container whose markup assignment builds fresh elements, as a parser
/// would: anything kept across a replacement comes from the keeper.
function container(build) {
  let markup = "";
  const root = { elements: [], replacements: 0,
    querySelectorAll: (selector) => selector === "*" ? root.elements
      : root.elements.filter((element) => element.tagName.toLowerCase() === selector) };
  Object.defineProperty(root, "innerHTML", {
    get: () => markup,
    set: (value) => { markup = value; root.replacements += 1; root.elements = build(value); },
  });
  return root;
}

test("a refresh of the same view returns each identified scrolled region to its offsets", () => {
  const keep = createScrollKeeper();
  const root = container(() => [
    region("DIV", { class: "settings-layout" }),
    region("PRE", { "data-log-view": "engine" }),
    region("SECTION", { class: "panel" }),
  ]);
  keep(root, "first", ["settings"]);
  const [list, log] = root.elements;
  list.scrollTop = 480; list.scrollLeft = 2; log.scrollLeft = 30;
  keep(root, "second", ["settings"]);
  assert.equal(root.innerHTML, "second");
  assert.notEqual(root.elements[0], list, "the markup was replaced");
  assert.deepEqual(root.elements.map(({ scrollTop, scrollLeft }) => [scrollTop, scrollLeft]), [[480, 2], [0, 30], [0, 0]]);
});

test("another view starts at the top, as navigation and a new dialog do", () => {
  for (const [before, after] of [[["settings"], ["rules"]], [[null, {}], [null, {}]], [["settings"], ["settings", null]]]) {
    const keep = createScrollKeeper();
    const root = container(() => [region("DIV", { class: "list" })]);
    keep(root, "first", before);
    root.elements[0].scrollTop = 99;
    keep(root, "second", after);
    assert.equal(root.elements[0].scrollTop, 0, JSON.stringify([before, after]));
  }
});

test("an ambiguous or unidentifiable region is replaced at the top", () => {
  const keep = createScrollKeeper();
  let duplicates = 1;
  const root = container(() => [
    ...Array.from({ length: duplicates }, () => region("UL", { class: "glass-list" })),
    region("DIV", {}),
    region("TEXTAREA", { style: "height: 80px" }),
  ]);
  keep(root, "first", ["dialog"]);
  for (const element of root.elements) element.scrollTop = 40;
  duplicates = 2;
  keep(root, "second", ["dialog"]);
  assert.deepEqual(root.elements.map(({ scrollTop }) => scrollTop), [0, 0, 0, 0]);
});

test("markup is replaced exactly once whether or not anything was scrolled", () => {
  const keep = createScrollKeeper();
  const root = container(() => [region("DIV", { class: "settings-layout" })]);
  keep(root, "first", ["settings"]);
  keep(root, "second", ["settings"]);
  keep(root, "third", ["rules"]);
  assert.equal(root.replacements, 3);
  assert.equal(root.innerHTML, "third");
});
