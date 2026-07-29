import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { UI_COMMANDS, UI_EVENTS } from "../src/format.js";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const uiRoot = path.resolve(testDirectory, "..");
const shellRoot = path.resolve(uiRoot, "..");
const rustRoot = path.join(shellRoot, "src");

/// Commands permanently retired in 0.4.0. No dashboard source file may mention
/// one, in an invoke, a comment, or a leftover string.
const RETIRED_COMMANDS = [
  "open_external_url",
  "set_engine_mode",
  "reapply_runtime_config",
  "enable_service_mode",
  "service_mode_status",
  "install_helper_service",
  "uninstall_helper_service",
  "start_core",
  "stop_core",
  "install_pinned_mihomo_core",
  "install_pinned_clash_rs_core",
  "install_latest_mihomo_core",
  "install_core_from_url",
  "provision_core_binary",
  "kernel_compare_report",
  "run_child_process",
  "run_tray_script",
  "core_status",
  "set_ipv6",
];

/// Events the webview itself emits. Everything else must be emitted by this
/// application's Rust sources.
const WEBVIEW_EVENTS = new Set(["tauri://drag-drop"]);

function filesUnder(root, extension) {
  const found = [];
  for (const entry of readdirSync(root)) {
    const candidate = path.join(root, entry);
    if (statSync(candidate).isDirectory()) {
      found.push(...filesUnder(candidate, extension));
    } else if (candidate.endsWith(extension)) {
      found.push(candidate);
    }
  }
  return found;
}

function readAll(files) {
  return files.map((file) => ({ file, source: readFileSync(file, "utf8") }));
}

const dashboardSources = readAll(filesUnder(path.join(uiRoot, "src"), ".js"));
const dashboardMarkup = readAll([path.join(uiRoot, "index.html")]);
const rustSources = readAll(filesUnder(rustRoot, ".rs"));
const mainRust = readFileSync(path.join(rustRoot, "main.rs"), "utf8");

function handlerCommands() {
  const start = mainRust.indexOf("tauri::generate_handler![");
  assert.notEqual(start, -1, "generate_handler! must exist in main.rs");
  const end = mainRust.indexOf("])", start);
  return new Set(
    mainRust
      .slice(start, end)
      .split("\n")
      .slice(1)
      .map((line) => line.trim().replace(/,$/u, ""))
      .filter((line) => /^[a-z][a-z0-9_]*$/u.test(line)),
  );
}

function emittedEvents() {
  const events = new Set();
  for (const { source } of rustSources) {
    for (const match of source.matchAll(/"(cfw:\/\/[a-z-]+)"/gu)) events.add(match[1]);
  }
  return events;
}

function dashboardMatches(pattern) {
  const found = new Map();
  for (const { file, source } of dashboardSources) {
    for (const match of source.matchAll(pattern)) {
      const existing = found.get(match[1]) ?? [];
      existing.push(path.relative(uiRoot, file));
      found.set(match[1], existing);
    }
  }
  return found;
}

const invoked = dashboardMatches(/invoke\("([a-z0-9_]+)"/gu);
const listened = dashboardMatches(/listen\("([a-z][a-z0-9:/-]+)"/gu);

test("every command the dashboard invokes exists in generate_handler!", () => {
  const handlers = handlerCommands();
  assert.equal(handlers.size, 80, "the release command surface is 80 commands");
  const missing = [...invoked.keys()].filter((command) => !handlers.has(command));
  assert.deepEqual(missing, [], `dashboard invokes commands that do not exist: ${missing.join(", ")}`);
});

test("the invoke allowlist is exactly the set of commands the dashboard invokes", () => {
  const allowlist = new Set(UI_COMMANDS);
  const notAllowed = [...invoked.keys()].filter((command) => !allowlist.has(command)).sort();
  assert.deepEqual(notAllowed, [], `invoked without being allowlisted: ${notAllowed.join(", ")}`);
  const unused = [...allowlist].filter((command) => !invoked.has(command)).sort();
  assert.deepEqual(unused, [], `allowlisted but never invoked: ${unused.join(", ")}`);
});

test("the renderer cannot invoke internal engine transitions or arbitrary URLs", () => {
  assert.equal(handlerCommands().has("open_external_url"), false);
  assert.equal(handlerCommands().has("set_engine_mode"), false);
  assert.equal(handlerCommands().has("reapply_runtime_config"), false);
});

test("every allowlisted command exists in generate_handler!", () => {
  const handlers = handlerCommands();
  const missing = UI_COMMANDS.filter((command) => !handlers.has(command));
  assert.deepEqual(missing, [], `allowlisted commands that do not exist: ${missing.join(", ")}`);
});

test("every event the dashboard listens for is actually emitted", () => {
  const emitted = emittedEvents();
  const missing = [...listened.keys()]
    .filter((event) => !WEBVIEW_EVENTS.has(event) && !emitted.has(event))
    .sort();
  assert.deepEqual(missing, [], `dashboard listens for events nothing emits: ${missing.join(", ")}`);
});

test("the listen allowlist is exactly the set of events the dashboard subscribes to", () => {
  const allowlist = new Set(UI_EVENTS);
  const notAllowed = [...listened.keys()].filter((event) => !allowlist.has(event)).sort();
  assert.deepEqual(notAllowed, [], `subscribed without being allowlisted: ${notAllowed.join(", ")}`);
  const unused = [...allowlist].filter((event) => !listened.has(event)).sort();
  assert.deepEqual(unused, [], `allowlisted but never subscribed: ${unused.join(", ")}`);
});

test("no retired command survives anywhere in the dashboard", () => {
  const offenders = [];
  for (const { file, source } of [...dashboardSources, ...dashboardMarkup]) {
    for (const command of RETIRED_COMMANDS) {
      if (source.includes(command)) offenders.push(`${path.relative(uiRoot, file)}: ${command}`);
    }
  }
  assert.deepEqual(offenders, [], `retired commands still referenced: ${offenders.join(", ")}`);
});

test("every rendered action has a handler", () => {
  const app = dashboardSources.find(({ file }) => file.endsWith("app.js")).source;
  const rendered = new Set(
    [...app.matchAll(/data-action="([a-z0-9-]+)"/gu)].map((match) => match[1]),
  );
  const handled = new Set(
    [...app.matchAll(/action === "([a-z0-9-]+)"/gu)].map((match) => match[1]),
  );
  const dead = [...rendered].filter((action) => !handled.has(action)).sort();
  assert.deepEqual(dead, [], `rendered actions with no handler: ${dead.join(", ")}`);
});

test("every profile menu item has a handler", () => {
  const app = dashboardSources.find(({ file }) => file.endsWith("app.js")).source;
  const menuBlock = app.slice(
    app.indexOf("const PROFILE_MENU_ACTIONS = ["),
    app.indexOf("function profileMenuIcon"),
  );
  const items = [...menuBlock.matchAll(/\{ id: "([a-z-]+)"/gu)].map((match) => match[1]);
  assert.ok(items.length >= 10, "the profile context menu keeps its 0.3.5 item set");
  const handled = new Set([...app.matchAll(/case "([a-z-]+)":/gu)].map((match) => match[1]));
  const dead = items.filter((item) => !handled.has(item));
  assert.deepEqual(dead, [], `profile menu items with no handler: ${dead.join(", ")}`);
});
