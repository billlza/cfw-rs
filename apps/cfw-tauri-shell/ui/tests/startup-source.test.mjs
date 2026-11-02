import { dom, element, host, settle } from "./support/fake-host.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

import { startStartupGuard } from "../src/startup-guard.js";

// Every scenario starts its own guard, as each page load does.
async function loadStartup() {
  startStartupGuard();
  return window.__CFM_STARTUP__;
}

function appendedPanel() {
  return document.getElementById("startup-recovery");
}

beforeEach(() => {
  host.reset();
  dom.reset();
  host.respond("report_dashboard_startup", null);
  delete window.__CFM_STARTUP__;
  document.body.appendChild = (node) => dom.byId(node.id, node);
  document.createElement = (tag) => {
    const node = element(tag);
    node.children = [];
    node.append = (...nodes) => node.children.push(...nodes);
    node.remove = () => dom.byId(node.id, null);
    return node;
  };
});

const reported = () => host.argsOf("report_dashboard_startup").map(({ code }) => code);
const panelText = () => appendedPanel().children.map((child) => child.textContent);

test("loading localizes the startup screen and reports that the script loaded", async () => {
  const label = dom.setAll("[data-i18n]", [element("span", { dataset: { i18n: "General" } })])[0];
  const screen = dom.set(".startup-screen", element("main"));
  await loadStartup();
  await settle();
  assert.equal(label.textContent, "General");
  assert.equal(screen.getAttribute("aria-label"), "Starting dashboard");
  assert.deepEqual(reported(), ["script_loaded"]);
});

test("a ready dashboard reports once and ignores later failures", async () => {
  const startup = await loadStartup();
  startup.ready();
  startup.ready();
  startup.fail();
  await settle();
  assert.deepEqual(reported(), ["script_loaded", "ready"]);
  assert.equal(appendedPanel(), null);
  assert.throws(() => { startup.extra = true; }, TypeError, "the startup handle is frozen");
});

test("a failed bootstrap shows a recovery panel whose buttons report their own failure", async () => {
  const startup = await loadStartup();
  startup.fail();
  startup.fail();
  await settle();
  assert.deepEqual(reported(), ["script_loaded", "bootstrap_failed"]);
  const [heading, , code, reload, logs, status] = appendedPanel().children;
  assert.equal(heading.textContent, "The dashboard could not finish starting");
  assert.equal(code.textContent, "Diagnostic code: bootstrap_failed");
  assert.match(status.textContent, /Diagnostic events are kept locally/u);
  host.respond("reload_dashboard", new Error("migration recovery"));
  await reload.fire("click");
  await settle();
  assert.match(status.textContent, /could not be reloaded/u);
  host.respond("reveal_logs_directory", new Error("no folder"));
  await logs.fire("click");
  await settle();
  assert.match(status.textContent, /Logs could not be opened/u);
  host.respond("reload_dashboard", null);
  await reload.fire("click");
  assert.deepEqual(host.commands().filter((command) => command === "reload_dashboard").length, 2);
  startup.ready();
  await settle();
  assert.deepEqual(reported(), ["script_loaded", "bootstrap_failed"], "a real failure is not cleared by a late ready");
});

test("a watchdog timeout is cleared by a late ready, and the panel follows a language change", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const startup = await loadStartup();
  t.mock.timers.tick(15000);
  await settle();
  assert.deepEqual(reported(), ["script_loaded", "startup_timeout"]);
  startup.setLanguage("zh-Hans");
  assert.equal(panelText()[0], "界面未能完成启动");
  startup.setLanguage("en");
  assert.ok(appendedPanel(), "the panel is shown again in the new language");
  startup.ready();
  await settle();
  assert.equal(appendedPanel(), null);
  assert.deepEqual(reported(), ["script_loaded", "startup_timeout", "ready"]);
});

test("script errors and unhandled rejections are startup failures", async () => {
  await loadStartup();
  const onError = window.listenerFor("error");
  onError({ target: { id: "other" } });
  await settle();
  assert.deepEqual(reported(), ["script_loaded"], "an unrelated resource error is not a startup failure");
  onError({ target: { id: "dashboard-script" } });
  await settle();
  assert.deepEqual(reported(), ["script_loaded", "script_failed"]);

  host.reset();
  host.respond("report_dashboard_startup", null);
  await loadStartup();
  window.listenerFor("error")({ error: new Error("boom") });
  await settle();
  assert.deepEqual(reported(), ["script_loaded", "script_failed"]);

  host.reset();
  host.respond("report_dashboard_startup", null);
  await loadStartup();
  window.listenerFor("error")({ message: "SyntaxError" });
  await settle();
  assert.deepEqual(reported(), ["script_loaded", "script_failed"]);

  host.reset();
  host.respond("report_dashboard_startup", null);
  await loadStartup();
  window.listenerFor("unhandledrejection")({});
  await settle();
  assert.deepEqual(reported(), ["script_loaded", "unhandled_rejection"]);
});

test("a diagnostic event that cannot be saved is stated in the panel", async () => {
  host.respond("report_dashboard_startup", new Error("disk full"));
  const note = dom.byId("startup-diagnostic-status", element("p"));
  const startup = await loadStartup();
  await settle();
  assert.match(note.textContent, /could not be saved/u);
  startup.fail();
  await settle();
  assert.match(panelText().at(-1), /could not be saved/u);
});

test("without the native bridge every report fails closed", async () => {
  const internals = window.__TAURI_INTERNALS__;
  window.__TAURI_INTERNALS__ = undefined;
  try {
    const note = dom.byId("startup-diagnostic-status", element("p"));
    await loadStartup();
    await settle();
    assert.match(note.textContent, /could not be saved/u);
  } finally {
    window.__TAURI_INTERNALS__ = internals;
  }
});

test("the startup entry starts the guard as soon as it loads", async () => {
  await import("../src/startup.js");
  await settle();
  assert.ok(Object.isFrozen(window.__CFM_STARTUP__));
  assert.deepEqual(reported(), ["script_loaded"]);
});
