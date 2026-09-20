import assert from "node:assert/strict";
import test from "node:test";
import { createEditingRender } from "../src/editing-render.js";

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
