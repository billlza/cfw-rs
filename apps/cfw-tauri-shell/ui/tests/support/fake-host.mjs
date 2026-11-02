// The WebView a dashboard module runs in, reduced to what the modules touch:
// a scripted Tauri host, a document of fake elements, the clipboard and frame
// and timer scheduling. Importing this module installs the globals, so it must
// be the first import of a test file.

/// One fake element. Listeners are recorded so a test can fire them, and every
/// fired listener's promise is awaited.
export function element(tag = "div", properties = {}) {
  const listeners = new Map();
  const node = {
    tagName: tag.toUpperCase(),
    dataset: {},
    style: { setProperty() {}, width: "", left: "", top: "" },
    classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
    attributes: new Map(),
    hidden: false,
    value: "",
    checked: false,
    disabled: false,
    textContent: "",
    innerHTML: "",
    scrollTop: 0,
    scrollHeight: 0,
    clientHeight: 0,
    files: [],
    focused: false,
    clicked: 0,
    selection: null,
    scrolledIntoView: [],
    addEventListener(type, listener) {
      const list = listeners.get(type) ?? [];
      list.push(listener);
      listeners.set(type, list);
    },
    removeEventListener() {},
    listenerCount: (type) => (listeners.get(type) ?? []).length,
    async fire(type, event = {}) {
      const full = {
        currentTarget: node,
        target: node,
        preventDefault() { full.defaultPrevented = true; },
        stopPropagation() { full.propagationStopped = true; },
        ...event,
      };
      for (const listener of listeners.get(type) ?? []) await listener(full);
      return full;
    },
    getBoundingClientRect: () => node.rect ?? { top: 0, bottom: 100, left: 0, right: 100, width: 100, height: 100 },
    querySelector: (selector) => node.children?.[selector] ?? null,
    querySelectorAll: () => [],
    getAttribute: (name) => node.attributes.get(name) ?? null,
    setAttribute(name, value) { node.attributes.set(name, String(value)); },
    hasAttribute: (name) => node.attributes.has(name),
    closest: (selector) => node.closestMap?.[selector] ?? null,
    focus() { node.focused = true; },
    blur() { node.focused = false; },
    setSelectionRange(start, end) { node.selection = [start, end]; },
    click() { node.clicked += 1; },
    scrollIntoView(options) { node.scrolledIntoView.push(options); },
    remove() {},
    appendChild() {},
    insertAdjacentHTML() {},
  };
  return Object.assign(node, properties);
}

const byId = new Map();
const one = new Map();
const all = new Map();
const documentListeners = new Map();

export const dom = {
  /// `document.querySelector(selector)` returns `node`.
  set(selector, node) { one.set(selector, node); return node; },
  /// `document.querySelectorAll(selector)` returns `nodes`.
  setAll(selector, nodes) { all.set(selector, nodes); return nodes; },
  /// `document.getElementById(id)` returns `node`.
  byId(id, node) { byId.set(id, node); return node; },
  listeners: (type) => documentListeners.get(type) ?? [],
  async fireDocument(type, event) {
    for (const listener of documentListeners.get(type) ?? []) await listener(event);
  },
  reset() {
    byId.clear();
    one.clear();
    all.clear();
    documentListeners.clear();
  },
};

globalThis.document = {
  documentElement: element("html"),
  body: element("body"),
  title: "",
  hidden: false,
  activeElement: null,
  getElementById: (id) => byId.get(id) ?? null,
  querySelector: (selector) => one.get(selector) ?? null,
  querySelectorAll: (selector) => all.get(selector) ?? [],
  createElement: (tag) => element(tag),
  addEventListener(type, listener) {
    const list = documentListeners.get(type) ?? [];
    list.push(listener);
    documentListeners.set(type, list);
  },
  removeEventListener() {},
};

const windowListeners = new Map();
export const timers = { intervals: [], frames: 0 };

/// The scripted host. A response is a value, a function of the arguments, or
/// an Error to reject with. Unscripted commands reject, so a test never passes
/// on a command it did not expect.
export const host = {
  responses: new Map(),
  calls: [],
  respond(command, response) { host.responses.set(command, response); },
  commands: () => host.calls.map(({ command }) => command),
  argsOf: (command) => host.calls.filter((call) => call.command === command).map(({ args }) => args),
  reset() {
    host.responses.clear();
    host.calls.length = 0;
  },
  /// Delivers `message` to the page through a Channel the page passed to the host.
  deliver(channel, message) {
    const index = channelIndexes.get(channel.id) ?? 0;
    channelIndexes.set(channel.id, index + 1);
    const callback = callbacks.get(channel.id);
    if (!callback) throw new Error(`channel ${channel.id} has no registered callback`);
    callback({ index, message });
  },
};

const callbacks = new Map();
const channelIndexes = new Map();
let nextCallback = 1;
globalThis.window = {
  document: globalThis.document,
  innerWidth: 900,
  innerHeight: 700,
  addEventListener(type, handler) { windowListeners.set(type, handler); },
  removeEventListener() {},
  listenerFor: (type) => windowListeners.get(type),
  requestAnimationFrame(callback) {
    timers.frames += 1;
    setImmediate(callback);
    return timers.frames;
  },
  setTimeout: (callback, delay) => setTimeout(callback, delay),
  clearTimeout: (handle) => clearTimeout(handle),
  setInterval(callback, delay) {
    timers.intervals.push({ callback, delay });
    return timers.intervals.length;
  },
  matchMedia: () => ({ matches: false }),
  __TAURI_INTERNALS__: {
    transformCallback(callback) {
      const id = nextCallback++;
      callbacks.set(id, callback);
      return id;
    },
    unregisterCallback(id) { callbacks.delete(id); },
    async invoke(command, args) {
      host.calls.push({ command, args });
      if (!host.responses.has(command)) throw new Error(`unscripted host command ${command}`);
      const response = host.responses.get(command);
      const value = typeof response === "function" ? await response(args) : response;
      if (value instanceof Error) throw value;
      return value;
    },
  },
};
globalThis.requestAnimationFrame = globalThis.window.requestAnimationFrame;

export const clipboard = { written: [], text: "", writeError: null, readError: null };
Object.defineProperty(globalThis, "navigator", {
  value: {
    hardwareConcurrency: 8,
    clipboard: {
      async writeText(value) {
        if (clipboard.writeError) throw clipboard.writeError;
        clipboard.written.push(value);
      },
      async readText() {
        if (clipboard.readError) throw clipboard.readError;
        return clipboard.text;
      },
    },
  },
  configurable: true,
});
globalThis.HTMLTextAreaElement = class {};
globalThis.HTMLInputElement = class {};
globalThis.HTMLSelectElement = class {};
globalThis.Element = class {};
globalThis.CSS = { escape: (value) => value };
globalThis.getComputedStyle = () => ({ lineHeight: "18px" });

/// Resolves once every queued microtask and immediate has run.
export const settle = () => new Promise((resolve) => setImmediate(resolve));

/// A recording stand-in for a collaborator function.
export function spy(implementation = () => undefined) {
  const calls = [];
  const fn = (...args) => {
    calls.push(args);
    return implementation(...args);
  };
  fn.calls = calls;
  fn.count = () => calls.length;
  return fn;
}
