import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../dist/startup.js", import.meta.url), "utf8");

function launch({ nativeFailure = false } = {}) {
  const elements = new Map();
  const listeners = new Map();
  const timers = new Map();
  const calls = [];
  let reloaded = 0;
  function element(tag) {
    return { tagName: tag.toUpperCase(), id: "", children: [], handlers: {}, textContent: "",
      setAttribute(key, value) { this[key] = value; },
      remove() { if (this.id) elements.delete(this.id); },
      addEventListener(name, handler) { this.handlers[name] = handler; },
      append(...children) { this.children.push(...children); },
      appendChild(child) {
        this.children.push(child);
        const register = (node) => { if (node.id) elements.set(node.id, node); node.children.forEach(register); };
        register(child);
      },
    };
  }
  const body = element("body");
  const window = {
    __TAURI_INTERNALS__: { invoke(command, args) {
      calls.push({ command, args });
      return nativeFailure ? Promise.reject(new Error("token=must-not-render")) : Promise.resolve();
    } },
    addEventListener(name, handler) { listeners.set(name, handler); },
    removeEventListener(name) { listeners.delete(name); },
    setTimeout(handler, duration) { assert.equal(duration, 15000); timers.set(1, handler); return 1; },
    clearTimeout(id) { timers.delete(id); },
    location: { reload() { reloaded += 1; } },
  };
  vm.runInNewContext(source, { window, document: { body, documentElement: element("html"), querySelectorAll: () => [], querySelector: () => null, createElement: element, getElementById: (id) => elements.get(id) }, Promise, Object, Error });
  return { window, body, elements, listeners, timers, calls, reloadCount: () => reloaded };
}

test("missing or unevaluable dashboard bundle leaves independent recovery controls", async () => {
  for (const event of [{ target: { id: "dashboard-script" } }, { error: new SyntaxError("private token=must-not-render") }]) {
    const app = launch();
    app.listeners.get("error")(event);
    const recovery = app.elements.get("startup-recovery");
    assert.ok(recovery);
    assert.equal(recovery.role, "alert");
    const text = recovery.children.map((node) => node.textContent).join(" ");
    assert.match(text, /renderer|script_failed/u);
    assert.doesNotMatch(text, /must-not-render/u);
    app.window.__CFM_STARTUP__.ready();
    assert.ok(app.elements.get("startup-recovery"), "real script failure cannot be erased by a late ready signal");
    recovery.children.find((node) => node.textContent === "Reload dashboard").handlers.click();
    assert.equal(app.reloadCount(), 0);
    assert.ok(app.calls.some(({ command }) => command === "reload_dashboard"));
    recovery.children.find((node) => node.textContent === "Open diagnostic logs").handlers.click();
    await Promise.resolve();
    assert.ok(app.calls.some(({ command }) => command === "reveal_logs_directory"));
    assert.ok(app.calls.every(({ command }) => ["report_dashboard_startup", "reveal_logs_directory", "reload_dashboard"].includes(command)));
  }
});

test("slow native preparation recovers only when the real bootstrap completes", () => {
  const app = launch();
  app.timers.get(1)();
  app.window.__CFM_STARTUP__.ready();
  assert.equal(app.elements.get("startup-recovery"), undefined);
  assert.equal(app.calls.filter(({ args }) => args?.code === "startup_timeout").length, 1);
  assert.equal(app.calls.filter(({ args }) => args?.code === "ready").length, 1);
  assert.equal(app.timers.size, 0);
});

test("successful startup removes its watchdog and does not turn later application errors into startup failures", () => {
  const app = launch();
  app.window.__CFM_STARTUP__.ready();
  assert.equal(app.timers.size, 0);
  assert.equal(app.listeners.size, 0);
  assert.equal(app.elements.has("startup-recovery"), false);
  assert.equal(app.calls.filter(({ args }) => args?.code === "ready").length, 1);
});

test("diagnostic storage failure stays visible without echoing native error text", async () => {
  const app = launch({ nativeFailure: true });
  await Promise.resolve();
  await Promise.resolve();
  app.window.__CFM_STARTUP__.fail();
  await Promise.resolve();
  assert.match(app.elements.get("startup-diagnostic-status").textContent, /could not be saved/u);
  assert.doesNotMatch(app.body.children.map((node) => node.textContent).join(" "), /must-not-render/u);
});

test("unhandled rejection during startup is explicit and does not invoke network controls", () => {
  const app = launch();
  app.listeners.get("unhandledrejection")({ reason: "private failure" });
  assert.ok(app.elements.get("startup-recovery"));
  assert.equal(app.calls.at(-1).args.code, "unhandled_rejection");
});

test("a rejected native reload never falls back to an unchecked renderer reload", async () => {
  const app = launch({ nativeFailure: true });
  app.window.__CFM_STARTUP__.fail();
  app.elements.get("startup-recovery").children.find((node) => node.textContent === "Reload dashboard").handlers.click();
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(app.reloadCount(), 0);
  assert.match(app.elements.get("startup-diagnostic-status").textContent, /could not be reloaded/u);
});

test("independent startup recovery uses the chosen language without invoking network controls", () => {
  for (const [locale, heading] of [["zh-Hans", "界面未能完成启动"], ["zh-Hant", "介面無法完成啟動"], ["ja", "画面の起動を完了できませんでした"]]) {
    const app = launch();
    app.window.__CFM_STARTUP__.setLanguage(locale);
    app.window.__CFM_STARTUP__.fail();
    const recovery = app.elements.get("startup-recovery");
    assert.equal(recovery.children[0].textContent, heading);
    assert.ok(app.calls.every(({ command }) => ["report_dashboard_startup", "reveal_logs_directory", "reload_dashboard"].includes(command)));
  }
});
