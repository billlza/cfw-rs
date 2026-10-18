// Preserve the active editor across a dashboard refresh. Values remain in the
// owning form state; this module retains only focus, selection and scroll state.
const EDITABLE_TAGS = new Set(["INPUT", "TEXTAREA", "SELECT"]);
const NON_TEXT_INPUTS = new Set(["button", "checkbox", "color", "file", "hidden", "radio", "range", "reset", "submit"]);

function sameContext(left, right) {
  return left?.length === right.length && left.every((value, index) => value === right[index]);
}

function describeEditor(document) {
  const field = document.activeElement;
  if (!EDITABLE_TAGS.has(field?.tagName) || (field.tagName === "INPUT" && NON_TEXT_INPUTS.has(field.type))) return null;
  const root = field.closest("#glass-menu-root, #page");
  if (!root) return null;
  const attributes = field.getAttributeNames()
    .filter((name) => name.startsWith("data-") || ["id", "name", "aria-label"].includes(name))
    .map((name) => [name, field.getAttribute(name)]);
  if (!attributes.length) return null;
  return {
    rootId: root.id, tag: field.tagName, attributes,
    start: field.selectionStart, end: field.selectionEnd, direction: field.selectionDirection,
    scrollTop: field.scrollTop, scrollLeft: field.scrollLeft,
  };
}

function restoreEditor(document, saved) {
  if (!saved) return;
  const root = document.getElementById(saved.rootId);
  if (!root) return;
  // Match literal attributes, without constructing a selector from their values.
  const matches = [...root.querySelectorAll(saved.tag.toLowerCase())].filter((field) =>
    saved.attributes.every(([name, value]) => field.getAttribute(name) === value));
  if (matches.length !== 1 || matches[0].disabled) return;
  const field = matches[0];
  field.focus({ preventScroll: true });
  if (Number.isInteger(saved.start) && Number.isInteger(saved.end)) {
    field.setSelectionRange(saved.start, saved.end, saved.direction ?? "none");
  }
  field.scrollTop = saved.scrollTop;
  field.scrollLeft = saved.scrollLeft;
}

export function createEditingRender({ document, requestFrame, rerender }) {
  let previousContext = null;
  let compositionTarget = null;
  let pending = false;
  let framePending = false;
  let bound = false;

  function bind() {
    if (bound) return;
    bound = true;
    document.addEventListener("compositionstart", (event) => {
      if (EDITABLE_TAGS.has(event.target?.tagName)) compositionTarget = event.target;
    });
    document.addEventListener("compositionend", (event) => {
      if (event.target !== compositionTarget) return;
      compositionTarget = null;
      if (!pending || framePending) return;
      framePending = true;
      // Let the final input event update its form state before replacing the DOM.
      requestFrame(() => {
        framePending = false;
        if (compositionTarget || !pending) return;
        pending = false;
        rerender();
      });
    });
  }

  function render(context, draw) {
    const unchanged = sameContext(previousContext, context);
    if (compositionTarget && unchanged) {
      pending = true;
      return;
    }
    // Navigation and closing/replacing a dialog are intentional context changes.
    if (!unchanged) compositionTarget = null;
    pending = false;
    const saved = unchanged ? describeEditor(document) : null;
    draw();
    previousContext = [...context];
    restoreEditor(document, saved);
  }

  return { bind, render };
}
