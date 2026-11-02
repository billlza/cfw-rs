// Preserve what a dashboard refresh replaces: the active editor (focus,
// selection and its own scroll) and the offsets of scrolled regions. Values
// remain in the owning form state; this module retains only view state.
const EDITABLE_TAGS = new Set(["INPUT", "TEXTAREA", "SELECT"]);
const NON_TEXT_INPUTS = new Set(["button", "checkbox", "color", "file", "hidden", "radio", "range", "reset", "submit"]);
const IDENTITY_ATTRIBUTES = ["id", "name", "aria-label"];
// A scroll container usually has only its class to tell it apart.
const REGION_IDENTITY_ATTRIBUTES = [...IDENTITY_ATTRIBUTES, "class"];

function sameContext(left, right) {
  return left?.length === right.length && left.every((value, index) => value === right[index]);
}

function identity(element, names = IDENTITY_ATTRIBUTES) {
  return element.getAttributeNames()
    .filter((name) => name.startsWith("data-") || names.includes(name))
    .map((name) => [name, element.getAttribute(name)]);
}

// Match literal attributes, without constructing a selector from their values.
function matching(root, tag, attributes) {
  return [...root.querySelectorAll(tag.toLowerCase())].filter((element) =>
    attributes.every(([name, value]) => element.getAttribute(name) === value));
}

function describeEditor(document) {
  const field = document.activeElement;
  if (!EDITABLE_TAGS.has(field?.tagName) || (field.tagName === "INPUT" && NON_TEXT_INPUTS.has(field.type))) return null;
  const root = field.closest("#glass-menu-root, #page");
  if (!root) return null;
  const attributes = identity(field);
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
  const matches = matching(root, saved.tag, saved.attributes);
  if (matches.length !== 1 || matches[0].disabled) return;
  const field = matches[0];
  field.focus({ preventScroll: true });
  if (Number.isInteger(saved.start) && Number.isInteger(saved.end)) {
    field.setSelectionRange(saved.start, saved.end, saved.direction ?? "none");
  }
  field.scrollTop = saved.scrollTop;
  field.scrollLeft = saved.scrollLeft;
}

// A scrolled element with nothing to identify it cannot be found again.
function scrolledRegions(container) {
  const regions = [];
  for (const element of container.querySelectorAll("*")) {
    if (element.scrollTop === 0 && element.scrollLeft === 0) continue;
    const attributes = identity(element, REGION_IDENTITY_ATTRIBUTES);
    if (attributes.length) regions.push({ tag: element.tagName, attributes, top: element.scrollTop, left: element.scrollLeft });
  }
  return regions;
}

/// Replaces a container's markup for one view: the identities of what it
/// shows, such as the page id or the open dialogs. While the view stays the
/// same, each scrolled region that the new markup carries exactly once
/// returns to its offsets; another view starts at the top, as navigation does.
export function createScrollKeeper() {
  let shown = null;
  return function replace(container, markup, view) {
    const regions = sameContext(shown, view) ? scrolledRegions(container) : [];
    container.innerHTML = markup;
    shown = [...view];
    for (const region of regions) {
      const matches = matching(container, region.tag, region.attributes);
      if (matches.length !== 1) continue;
      matches[0].scrollTop = region.top;
      matches[0].scrollLeft = region.left;
    }
  };
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
