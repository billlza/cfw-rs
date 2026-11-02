import { clipboard, dom, element, host, settle, spy, timers } from "./support/fake-host.mjs";
import { replaceEngineIdentity, runEngine, stopEngine, streamBinding } from "./support/engine.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { PAGES, state, runtime } from "../src/state.js";
import { createGlobalEvents } from "../src/global-events.js";
import { createHostEvents } from "../src/host-events.js";
import { createPageShell } from "../src/page-shell.js";
import { createUpdateController } from "../src/update-controller.js";
import { createDiagnosticsDialogs } from "../src/diagnostics-dialogs.js";
import { generalIconButton, profileMenuIcon, renderInlineSwitch, renderToggle } from "../src/controls.js";

const lastLog = () => state.logs[0];

beforeEach(() => {
  host.reset();
  dom.reset();
  clipboard.written.length = 0;
  state.logs = [];
  state.payload = { product: { name: "Clash for Mac", version: "0.5.1", license: "GPL-3.0-or-later", operating_system: "macos", architecture: "arm64", minimum_os_version: "15.0" }, native_ui: {} };
  state.activePage = "general";
  state.glassDialog = null;
  state.logFilter = "all";
  state.logsPaused = false;
  state.connectionPaused = false;
  state.migrationHandoff = false;
  state.updateInfo = null;
  runtime.globalEventsBound = false;
  for (const lane of [runtime.connectionsLiveStream, runtime.logLiveStream]) {
    lane.binding = null;
    lane.operation = Promise.resolve();
  }
  stopEngine();
});

function globalEvents(overrides = {}) {
  const d = {
    editingRender: { bind: spy() }, followWindowResize: spy(), overlayOpen: () => false, closeGlassOverlays: spy(),
    handleAction: spy(async () => undefined), applyProxyMode: spy(async () => true), applyToggle: spy(async () => true),
    renderPage: spy(), patchLogStream: spy(), ...overrides,
  };
  createGlobalEvents(d).bindGlobalEvents();
  return d;
}

const asElement = (node) => Object.setPrototypeOf(node, Element.prototype);

test("global events bind once: Escape closes an open overlay and a resize follows the window", async () => {
  let open = true;
  const d = globalEvents({ overlayOpen: () => open });
  createGlobalEvents(d).bindGlobalEvents();
  assert.equal(d.editingRender.bind.count(), 1, "a second binding is refused");
  assert.equal(window.listenerFor("resize"), d.followWindowResize);
  const escape = { key: "Escape", preventDefault: spy() };
  await dom.fireDocument("keydown", escape);
  assert.equal(d.closeGlassOverlays.count(), 1);
  open = false;
  await dom.fireDocument("keydown", { key: "Escape", preventDefault: spy() });
  assert.equal(d.closeGlassOverlays.count(), 1, "nothing to close");
});

test("a log filter click changes the filter in place and a repeated filter changes nothing", async () => {
  const d = globalEvents();
  const info = element("button", { dataset: { logFilter: "info" } });
  const all = element("button", { dataset: { logFilter: "all" } });
  const selected = [];
  for (const button of [info, all]) button.classList.toggle = (name, on) => selected.push([button.dataset.logFilter, on]);
  dom.setAll("[data-log-filter]", [info, all]);
  const click = (target) => ({ target, preventDefault: spy(), stopPropagation: spy() });
  const inner = { parentElement: asElement(element("span", { closestMap: { "[data-log-filter]": info } })) };
  await dom.fireDocument("click", click(inner));
  assert.equal(state.logFilter, "info");
  assert.deepEqual(selected, [["info", true], ["all", false]]);
  assert.equal(info.getAttribute("aria-pressed"), "true");
  assert.equal(d.patchLogStream.count(), 1);
  await dom.fireDocument("click", click(inner));
  assert.equal(d.patchLogStream.count(), 1, "the active filter is not applied again");
  const blank = asElement(element("button", { dataset: {}, closestMap: { "[data-log-filter]": element("button", { dataset: {} }) } }));
  await dom.fireDocument("click", click(blank));
  assert.equal(state.logFilter, "all", "a filter button without a level means all");
});

test("an action control dispatches its action, and a refusal is logged and rendered", async () => {
  let fail = false;
  const d = globalEvents({ handleAction: spy(async () => { if (fail) throw new Error("refused"); }) });
  const button = element("button", { dataset: { action: "reload-proxies" } });
  const target = asElement(element("span", { closestMap: { "[data-action]": button } }));
  const event = { target, preventDefault: spy(), stopPropagation: spy() };
  await dom.fireDocument("click", event);
  assert.deepEqual(d.handleAction.calls, [["reload-proxies"]]);
  assert.equal(event.preventDefault.count(), 1);
  fail = true;
  await dom.fireDocument("click", { target, preventDefault: spy(), stopPropagation: spy() });
  await settle();
  assert.equal(lastLog().message, "refused");
  assert.equal(d.renderPage.count(), 1);
  await dom.fireDocument("click", { target: asElement(element("div")), preventDefault: spy(), stopPropagation: spy() });
  assert.equal(d.handleAction.count(), 2, "a click outside any action does nothing");
  await dom.fireDocument("click", { target: null, preventDefault: spy(), stopPropagation: spy() });
});

test("keyboard shortcuts switch pages and modes outside text fields", async () => {
  const d = globalEvents();
  const key = (value, extra = {}) => ({ key: value, metaKey: true, ctrlKey: false, altKey: false, target: element("div"), preventDefault: spy(), ...extra });
  await dom.fireDocument("keydown", key("2"));
  assert.equal(state.activePage, "proxies");
  assert.equal(lastLog().message, "Opened Proxies");
  await dom.fireDocument("keydown", key("2", { metaKey: false }));
  await dom.fireDocument("keydown", key("3", { altKey: true }));
  assert.equal(state.activePage, "proxies", "only Command or Control without Option counts");
  const field = Object.setPrototypeOf(element("input"), HTMLInputElement.prototype);
  await dom.fireDocument("keydown", key("3", { target: field }));
  await dom.fireDocument("keydown", key("g", { target: { isContentEditable: true } }));
  assert.equal(state.activePage, "proxies", "text fields keep their own shortcuts");
  assert.equal(d.applyProxyMode.count(), 0);
  for (const value of ["g", "r", "d"]) await dom.fireDocument("keydown", key(value));
  assert.deepEqual(d.applyProxyMode.calls, [["Global"], ["Rule"], ["Direct"]]);
  state.engine = { ...state.engine, desiredMode: "tunnel" };
  await dom.fireDocument("keydown", key("P"));
  await dom.fireDocument("keydown", key("t", { metaKey: false, ctrlKey: true }));
  assert.deepEqual(d.applyToggle.calls, [["systemProxy", true, "shortcut"], ["tunMode", false, "shortcut"]]);
  await dom.fireDocument("keydown", key("s"));
  assert.deepEqual(d.handleAction.calls, [["save-settings"]]);
  await dom.fireDocument("keydown", key("x"));
  const failing = globalEvents({ applyProxyMode: spy(async () => { throw new Error("no controller"); }) });
  runtime.globalEventsBound = false;
  createGlobalEvents(failing).bindGlobalEvents();
  await dom.fireDocument("keydown", key("g"));
  await settle();
  assert.equal(lastLog().message, "no controller");
});

function hostEvents(overrides = {}) {
  const d = {
    renderPage: spy(), scheduleRender: spy(), updateStatusBar: spy(), applyPersistedSettings: spy(),
    loadSettingsSnapshot: spy(async () => undefined), resetPersistedSettingsToSafeState: spy(),
    loadEngineStatus: spy(async () => true), loadRuntimeProjection: spy(async () => true), applyUpdateInfo: spy(),
    openProductAboutDialog: spy(), updateInstall: { onProgress: spy() }, scheduleConnectionsPatch: spy(),
    scheduleLogStreamPatch: spy(), importProfileFromPath: spy(async () => undefined), ...overrides,
  };
  return { d, events: createHostEvents(d) };
}

test("page and settings events apply, and an invalid settings event recovers or disables preferences", async () => {
  const { d, events } = hostEvents({ applyPersistedSettings: spy(() => { throw new Error("bad snapshot"); }) });
  events.onPage({ payload: "logs" });
  assert.equal(state.activePage, "logs");
  await events.onSettingsChanged({ payload: {} });
  assert.ok(state.logs.some((entry) => entry.message === "Rejected an invalid settings update: bad snapshot"));
  assert.equal(lastLog().message, "Preferences were recovered from the native store after an invalid update event.");
  const broken = hostEvents({
    applyPersistedSettings: spy(() => { throw new Error("bad snapshot"); }),
    loadSettingsSnapshot: spy(async () => { throw new Error("store unreadable"); }),
  });
  await broken.events.onSettingsChanged({ payload: {} });
  assert.equal(broken.d.resetPersistedSettingsToSafeState.count(), 1);
  assert.match(state.settingsUnavailableReason, /Preferences are unavailable/u);
  assert.equal(lastLog().message, "Native settings recovery failed: store unreadable");
  state.settingsUnavailableReason = null;
  const ok = hostEvents();
  await ok.events.onSettingsChanged({ payload: { theme: "dark" } });
  assert.deepEqual(ok.d.applyPersistedSettings.calls, [[{ theme: "dark" }]]);
  assert.equal(ok.d.loadEngineStatus.count(), 1);
  assert.ok(d.renderPage.count() >= 2);
});

test("update events refresh the About dialog and only the pages that show updates", () => {
  const { d, events } = hostEvents();
  state.activePage = "logs";
  events.onUpdateAvailable({ payload: { available: true, version: "0.5.2" } });
  assert.equal(d.renderPage.count(), 0);
  assert.equal(d.openProductAboutDialog.count(), 0);
  state.glassDialog = { kind: "product-about" };
  for (const page of ["general", "settings", "feedback"]) {
    state.activePage = page;
    events.onUpdateAvailable({ payload: { available: true, version: "0.5.2" } });
  }
  assert.equal(d.renderPage.count(), 3);
  assert.deepEqual(d.openProductAboutDialog.calls[0], [{ autoCheck: true, phase: "idle", result: { available: true, version: "0.5.2" } }]);
  events.onUpdateProgress({ payload: { downloaded: 1 } });
  assert.deepEqual(d.updateInstall.onProgress.calls, [[{ downloaded: 1 }]]);
});

test("stream events apply only to the bound stream of the running engine", async () => {
  const { d, events } = hostEvents();
  runEngine();
  runtime.connectionsLiveStream.binding = streamBinding("connections", 7);
  runtime.logLiveStream.binding = streamBinding("request-logs", 8);
  const envelope = (stream, id, payload) => ({ provenance: streamBinding(stream, id), payload });
  events.onConnectionsSnapshot({ payload: envelope("connections", 7, { connections: [] }) });
  assert.equal(d.updateStatusBar.count(), 1);
  assert.equal(d.scheduleConnectionsPatch.count(), 0, "another page keeps its DOM");
  state.activePage = "connections";
  events.onConnectionsSnapshot({ payload: envelope("connections", 7, { connections: [] }) });
  assert.equal(d.scheduleConnectionsPatch.count(), 1);
  events.onConnectionsSnapshot({ payload: envelope("connections", 99, { connections: [] }) });
  assert.equal(d.updateStatusBar.count(), 2, "a stale stream id is ignored");
  state.connectionPaused = true;
  events.onConnectionsSnapshot({ payload: envelope("connections", 7, { connections: [] }) });
  assert.equal(d.updateStatusBar.count(), 2, "a paused stream is ignored");

  state.activePage = "logs";
  events.onLogLines({ payload: envelope("request-logs", 8, [{ level: "warn", message: "slow" }]) });
  assert.equal(lastLog().message, "slow");
  assert.equal(d.scheduleLogStreamPatch.count(), 1);
  events.onLogLines({ payload: envelope("request-logs", 99, [{ message: "stale" }]) });
  state.logsPaused = true;
  events.onLogLines({ payload: envelope("request-logs", 8, [{ message: "paused" }]) });
  assert.equal(lastLog().message, "slow");

  events.onStreamError({ payload: envelope("request-logs", 8, { stream: "request-logs", message: "stream closed" }) });
  assert.equal(lastLog().message, "stream closed");
  assert.equal(d.scheduleLogStreamPatch.count(), 2);
  state.activePage = "connections";
  events.onStreamError({ payload: envelope("connections", 7, { stream: "connections", level: "warning" }) });
  assert.equal(lastLog().level, "warning");
  assert.equal(lastLog().message, "stream unavailable");
  assert.equal(d.scheduleRender.count(), 1);
  events.onStreamError({ payload: envelope("connections", 7, { stream: "request-logs" }) });
  events.onStreamError({ payload: { provenance: { stream: "telemetry" }, payload: {} } });
  assert.equal(d.scheduleRender.count(), 1, "mismatched or unknown streams are ignored");
  state.activePage = "general";
  events.onStreamError({ payload: envelope("connections", 7, { stream: "connections" }) });
  assert.equal(d.scheduleRender.count(), 1);
});

test("engine events re-read the engine, reload the boot state for a handoff and are logged otherwise", async () => {
  const { d, events } = hostEvents();
  host.respond("start_connections_stream", streamBinding("connections"));
  host.respond("start_log_stream", streamBinding("request-logs"));
  host.respond("legacy_retirement_status", { state: "cleared" });
  await events.onEngineSnapshot();
  assert.equal(d.loadEngineStatus.count(), 1);
  runEngine();
  host.respond("controller_snapshot", null);
  await events.onEngineEvent({ payload: { type: "snapshot_changed" } });
  assert.equal(d.loadRuntimeProjection.count(), 1);
  assert.equal(host.argsOf("controller_snapshot").length, 2, "a running engine is read back twice at most");
  stopEngine();

  host.respond("boot_payload", new Error("boot unreadable"));
  state.activePage = "logs";
  await events.onEngineEvent({ payload: { code: "migration_handoff_failed", message: "handoff failed" } });
  assert.equal(state.migrationHandoffStatus.code, "migration_handoff_task_failed");
  assert.equal(d.scheduleLogStreamPatch.count(), 1);
  state.migrationHandoff = true;
  await events.onEngineEvent({ payload: { code: "migration_handoff_failed" } });
  assert.equal(host.argsOf("boot_payload").length, 1, "a handoff window never requests another boot challenge");
  await events.onEngineEvent({});
  assert.equal(lastLog().level, "error");
});

test("dropped files import only profiles and say when nothing could be imported", async () => {
  const { d, events } = hostEvents();
  await events.onDragDrop({ payload: { paths: [] } });
  await events.onDragDrop({});
  assert.equal(state.logs.length, 0);
  await events.onDragDrop({ payload: { paths: ["/tmp/photo.png"] } });
  assert.equal(lastLog().message, "Drag-drop requires a JSON, YAML, or node-link text profile");
  await events.onDragDrop({ payload: { paths: ["/tmp/a.yaml", "/tmp/b.png", "/tmp/c.json"] } });
  assert.deepEqual(d.importProfileFromPath.calls, [["/tmp/a.yaml"], ["/tmp/c.json"]]);
});

function pageShell(overrides = {}) {
  const renderers = Object.fromEntries(PAGES.map(({ id }) => [id, () => `<p>${id}</p>`]));
  const d = {
    editingRender: { render: (keys, render) => render() }, replacePageMarkup: spy((node, markup) => { node.innerHTML = markup; }),
    windowGlass: { refresh: spy() }, nativeGeneralSwitches: { beforeRender: spy(), refresh: spy() },
    renderGlassOverlays: spy(), bindPageEvents: spy(), pageRenderers: renderers, ...overrides,
  };
  return { d, shell: createPageShell(d) };
}

test("the page shell refuses a renderer table that differs from the shared page contract", () => {
  const renderers = Object.fromEntries(PAGES.map(({ id }) => [id, () => ""]));
  delete renderers.logs;
  assert.throws(() => pageShell({ pageRenderers: renderers }), /must exactly match the shared page contract/u);
  assert.throws(() => pageShell({ pageRenderers: { ...renderers, logs: () => "", extra: () => "" } }), /must exactly match/u);
  assert.throws(() => pageShell({ pageRenderers: { ...renderers, extra: () => "" } }), /must exactly match/u);
});

test("rendering a page fills the shell, binds it and refreshes the native layers", async () => {
  const { d, shell } = pageShell();
  for (const id of ["page", "nav", "page-title", "page-summary", "product-name", "status-title", "sidebar-status", "sidebar-status-dot"]) dom.byId(id, element("div"));
  state.activePage = "logs";
  state.mode = "Rule";
  shell.renderPage();
  assert.equal(document.getElementById("page").innerHTML, "<p>logs</p>");
  assert.equal(document.getElementById("status-title").textContent, "Logs - Rule Mode");
  assert.equal(document.getElementById("sidebar-status").textContent, "Disconnected");
  assert.match(document.getElementById("nav").innerHTML, /data-page="general"/u);
  assert.equal(d.bindPageEvents.count(), 1);
  assert.equal(d.renderGlassOverlays.count(), 1);
  runEngine();
  state.mode = null;
  shell.renderPage();
  assert.equal(document.getElementById("status-title").textContent, "Logs");
  assert.equal(document.getElementById("sidebar-status-dot").className, "on");
  const editor = Object.setPrototypeOf(element("textarea", { value: "{\"route\": {}}" }), HTMLTextAreaElement.prototype);
  dom.set("[data-profile-editor]", editor);
  state.profileInspector = { mode: "edit", focusKey: "route" };
  shell.renderPage();
  await settle();
  assert.equal(editor.focused, true, "the inspector's section is focused after the frame");
  state.profileInspector = null;
  const bare = pageShell({ pageRenderers: { ...Object.fromEntries(PAGES.map(({ id }) => [id, () => ""])), logs: "not a function" } });
  assert.throws(() => bare.shell.renderPage(), /renderer is unavailable for page logs/u);
});

test("the status bar writes only changed values and the clock advances while the engine runs", async (t) => {
  const { shell } = pageShell();
  shell.updateStatusBar();
  const nodes = Object.fromEntries(["upload-rate", "download-rate", "runtime-value", "traffic-progress"].map((id) => [id, dom.byId(id, element("div"))]));
  state.traffic.upload = 1;
  state.traffic.download = 2;
  state.traffic.runtimeSeconds = 61;
  shell.updateStatusBar();
  assert.equal(nodes["traffic-progress"].style.width, "12%");
  assert.equal(nodes["runtime-value"].textContent.length > 0, true);
  t.mock.timers.enable({ apis: ["Date"], now: 1_000_000 });
  const before = timers.intervals.length;
  shell.startStatusClock();
  const clock = timers.intervals.at(-1);
  assert.equal(timers.intervals.length, before + 1);
  assert.equal(clock.delay, 1000);
  runEngine();
  state.engineStartedAt = null;
  clock.callback();
  t.mock.timers.tick(5000);
  clock.callback();
  assert.equal(state.traffic.runtimeSeconds, 5);
  stopEngine();
  clock.callback();
  assert.equal(state.traffic.runtimeSeconds, 0);
  assert.equal(state.engineStartedAt, null);
});

test("frames coalesce: one render and one glass refresh per burst", async () => {
  const { d, shell } = pageShell();
  dom.byId("page", element("section"));
  dom.byId("nav", element("nav"));
  dom.byId("page-title", element("h1"));
  dom.byId("page-summary", element("p"));
  const frames = timers.frames;
  shell.scheduleRender();
  shell.scheduleRender();
  assert.equal(timers.frames, frames + 1);
  await settle();
  assert.equal(d.bindPageEvents.count(), 1);
  shell.followWindowResize();
  shell.followWindowResize();
  await settle();
  assert.equal(d.windowGlass.refresh.count(), 2, "one refresh for the render, one for the resize burst");
});

function updates(overrides = {}) {
  const d = { renderPage: spy(), renderGlassOverlays: spy(), overlayOpen: () => false, closeGlassOverlays: spy(), ...overrides };
  return { d, controller: createUpdateController(d) };
}

test("checking for updates shows the result or the failure in the About dialog", async () => {
  const { d, controller } = updates();
  host.respond("check_for_updates", { available: true, version: "0.5.2", current: "0.5.1", notes: "Fixes" });
  await controller.actions["check-for-updates"]();
  assert.equal(state.glassDialog.kind, "product-about");
  assert.equal(state.glassDialog.payload.update.version, "0.5.2");
  assert.equal(state.updateInfo.available, true);
  host.respond("check_for_updates", new Error("rate limited"));
  await controller.actions["check-for-updates"]();
  assert.equal(lastLog().message, "Update check failed: rate limited");
  assert.equal(state.updateInfo.available, false, "a failed check withdraws the earlier offer");
  assert.equal(state.glassDialog.payload.update.error, "rate limited");
  assert.equal(d.renderPage.count(), 2);
  controller.applyUpdateInfo(null);
  assert.equal(state.updateInfo.error, "rate limited", "an empty payload changes nothing");
});

test("the About dialog states checking, available, current and failed updates", () => {
  const { controller } = updates();
  const render = (payload) => controller.dialogs.render({ kind: "product-about", payload });
  let html = render({ phase: "checking", update: null });
  assert.match(html, /Checking for updates…/u);
  assert.match(html, /data-glass-check-update disabled/u);
  html = render({ checking: true, update: null });
  assert.match(html, /Checking for updates…/u);
  html = render({ phase: "idle", update: { available: true, version: "0.5.2", notes: "x".repeat(400) } });
  assert.match(html, /Update available: v0\.5\.2/u);
  assert.match(html, /data-glass-open-update>Open Download v0\.5\.2/u);
  assert.match(html, new RegExp(`<p class="product-about-notes">${"x".repeat(280)}</p>`, "u"));
  html = render({ phase: "idle", update: { available: false, current: "0.5.1" } });
  assert.match(html, /You’re up to date \(v0\.5\.1\)/u);
  html = render({ phase: "idle", update: { available: false } });
  assert.match(html, /You’re up to date \(v0\.5\.1\)/u);
  html = render({ phase: "idle", update: { error: "rate limited" } });
  assert.match(html, /Update failed: rate limited/u);
  html = render({});
  assert.match(html, /Check GitHub releases for new builds\./u);
  state.payload.product.minimum_os_version = null;
  state.payload.product.version = null;
  html = render({});
  assert.match(html, /arm64 · macOS<\/div>/u);
});

test("an earlier installation's notice is shown unless another overlay is open", async () => {
  let open = true;
  const { d, controller } = updates({ overlayOpen: () => open });
  host.respond("resolve_update_install", new Error("journal unreadable"));
  await controller.updateInstall.resolveOutcome();
  assert.equal(state.glassDialog, null, "an open overlay is not replaced; the log carries the notice");
  assert.match(lastLog().message, /^The previous update attempt could not be reviewed: .*journal unreadable/u);
  open = false;
  await controller.updateInstall.resolveOutcome();
  assert.deepEqual(state.glassDialog, { kind: "info", payload: { title: "Updates", body: lastLog().message } });
  assert.equal(d.renderGlassOverlays.count(), 1);
});

test("the About dialog's install, commit and cancel buttons each run their installation step", async () => {
  const { controller } = updates();
  const steps = { install: "prepare", commit: "commit", cancel: "cancel" };
  const buttons = {};
  for (const [name, method] of Object.entries(steps)) {
    controller.updateInstall[method] = spy(async () => undefined);
    buttons[name] = element("button");
    dom.setAll(`[data-glass-update-${name}]`, [buttons[name]]);
  }
  controller.dialogs.bind();
  for (const [name, method] of Object.entries(steps)) {
    await buttons[name].fire("click");
    assert.equal(controller.updateInstall[method].count(), 1, name);
  }
});

test("the About dialog checks again, opens the download page and reports a refusal", async () => {
  const { d, controller } = updates();
  const check = element("button");
  const open = element("button");
  dom.setAll("[data-glass-check-update]", [check]);
  dom.setAll("[data-glass-open-update]", [open]);
  controller.dialogs.bind();
  host.respond("check_for_updates", { available: false, current: "0.5.1" });
  await check.fire("click");
  assert.equal(lastLog().message, "Already up to date (0.5.1)");
  assert.equal(state.glassDialog.payload.phase, "idle");
  host.respond("check_for_updates", { available: true, version: "0.5.2" });
  await check.fire("click");
  assert.equal(lastLog().message, "Update 0.5.2 available");
  host.respond("check_for_updates", new Error("offline"));
  await check.fire("click");
  assert.equal(lastLog().message, "Update check failed: offline");

  state.updateInfo = { version: null };
  await open.fire("click");
  assert.equal(lastLog().message, "Could not open update: No validated update is available");
  state.updateInfo = { version: "0.5.2" };
  host.respond("open_available_update", null);
  await open.fire("click");
  assert.deepEqual(host.argsOf("open_available_update"), [{ expectedVersion: "0.5.2" }]);
  assert.equal(lastLog().message, "Official v0.5.2 download page opened");
  assert.equal(d.closeGlassOverlays.count(), 1);
  state.updateInfo = { version: "0.5.2" };
  host.respond("open_available_update", new Error("checksum mismatch"));
  await open.fire("click");
  assert.equal(lastLog().message, "Could not open update: checksum mismatch");
  assert.equal(state.updateInfo.available, false);
});

function diagnostics(overrides = {}) {
  const d = { renderPage: spy(), renderGlassOverlays: spy(), runtimeProjectionActionAllowed: () => true, ...overrides };
  return { d, dialogs: createDiagnosticsDialogs(d) };
}

test("the diagnostics dialogs render the configuration, the network services and a DNS query", () => {
  const { dialogs } = diagnostics();
  assert.match(dialogs.dialogs.render({ kind: "preview-config", payload: "{\"log\":{}}" }), /<pre class="glass-code">\{&quot;log&quot;:\{\}\}<\/pre>/u);
  assert.match(dialogs.dialogs.render({ kind: "preview-config" }), /<pre class="glass-code"><\/pre>/u);
  const services = dialogs.dialogs.render({ kind: "network-services", payload: { services: [{ display_name: "Wi-Fi", order: 1, web: { enabled: true } }] } });
  assert.match(services, /<td>Wi-Fi<\/td><td>1<\/td><td>HTTP<\/td>/u);
  assert.match(dialogs.dialogs.render({ kind: "network-services", payload: { services: [] } }), /colspan="3">No services/u);
  assert.match(dialogs.dialogs.render({ kind: "dns-query", payload: {} }), /value="www\.gstatic\.com"[\s\S]*value="A"[\s\S]*Enter a name and Query\./u);
  assert.throws(() => dialogs.dialogs.render({ kind: "info" }), /diagnostics dialog info is unknown/u);
});

test("a DNS query needs a running engine and shows the answer or the failure of that engine", async () => {
  const { d, dialogs } = diagnostics();
  const query = element("button");
  dom.setAll("[data-glass-dns-confirm]", [query]);
  dom.set("[data-glass-dns-name]", element("input", { value: " example.test " }));
  dom.set("[data-glass-dns-type]", element("input", { value: " " }));
  dialogs.dialogs.bind();
  await query.fire("click");
  assert.deepEqual(state.glassDialog.payload, { name: "example.test", type: "A", result: "Engine is Off; start the engine before querying DNS." });
  runEngine();
  host.respond("dns_query", { answers: ["1.2.3.4"] });
  await query.fire("click");
  assert.deepEqual(host.argsOf("dns_query"), [{ name: "example.test", record_type: "A", recordType: "A" }]);
  assert.match(state.glassDialog.payload.result, /1\.2\.3\.4/u);
  host.respond("dns_query", new Error("NXDOMAIN"));
  await query.fire("click");
  assert.equal(state.glassDialog.payload.result, "NXDOMAIN");
  assert.equal(lastLog().message, "DNS query failed: NXDOMAIN");
  const renders = d.renderGlassOverlays.count();
  host.respond("dns_query", () => { replaceEngineIdentity(); return { answers: [] }; });
  await query.fire("click");
  runEngine();
  host.respond("dns_query", () => { replaceEngineIdentity(); return new Error("late"); });
  await query.fire("click");
  assert.equal(d.renderGlassOverlays.count(), renders, "an answer for an earlier engine is dropped");
  dom.reset();
  dom.setAll("[data-glass-dns-confirm]", [query]);
  stopEngine();
  createDiagnosticsDialogs(d).dialogs.bind();
  await query.fire("click");
  assert.deepEqual(state.glassDialog.payload, { name: "", type: "A", result: "Engine is Off; start the engine before querying DNS." });
});

test("diagnostics actions open their dialogs or report why they cannot", async () => {
  const { d, dialogs } = diagnostics();
  host.respond("network_diagnostics", { services: [] });
  await dialogs.actions["show-network-interfaces"]();
  assert.deepEqual(state.glassDialog, { kind: "network-services", payload: { services: [] } });
  host.respond("network_diagnostics", { platform: "linux" });
  await dialogs.actions["show-network-interfaces"]();
  assert.equal(lastLog().message, "Network diagnostics platform is invalid");
  host.respond("read_runtime_config_text", "{}");
  await dialogs.actions["preview-runtime-config"]();
  assert.deepEqual(state.glassDialog, { kind: "preview-config", payload: "{}" });
  host.respond("read_runtime_config_text", new Error("projection failed"));
  await dialogs.actions["preview-runtime-config"]();
  assert.equal(lastLog().message, "Configuration preview failed: projection failed");
  const refused = diagnostics({ runtimeProjectionActionAllowed: () => false });
  await refused.dialogs.actions["preview-runtime-config"]();
  assert.equal(refused.d.renderPage.count(), 0);
  await dialogs.actions["dns-query"]();
  assert.deepEqual(state.glassDialog, { kind: "dns-query", payload: { name: "www.gstatic.com", type: "A", result: "" } });
  assert.equal(d.renderPage.count(), 2);
});

test("switch rows state why a switch is unavailable and keep an on switch removable", () => {
  state.toggles.silentStart = true;
  let html = renderToggle("silentStart", "Silent start", "hint");
  assert.match(html, /<small>hint<\/small>/u);
  assert.match(html, /checked/u);
  html = renderToggle("silentStart", "Silent start", "hint", { reason: "unavailable" });
  assert.match(html, /toggle-row disabled/u);
  assert.match(html, /title="unavailable"/u);
  assert.doesNotMatch(html, /checked/u);
  html = renderToggle("silentStart", "Silent start", "hint", { reason: "unavailable", allowDisableWhenUnavailable: true });
  assert.match(html, /checked/u);
  assert.doesNotMatch(html, /disabled/u, "an on switch stays removable");
  html = renderToggle("silentStart", "Silent start", "hint", { disabled: true });
  assert.match(html, /disabled/u);
  html = renderInlineSwitch("silentStart", "Silent start", { title: "tip" });
  assert.match(html, /title="tip"/u);
  assert.match(html, /Silent start — tip/u);
  html = renderInlineSwitch("silentStart", "Silent start", { reason: "no", allowDisableWhenUnavailable: true });
  assert.match(html, /checked/u);
  html = renderInlineSwitch("silentStart", "Silent start");
  assert.doesNotMatch(html, /title=/u);
  state.toggles.silentStart = false;
  assert.doesNotMatch(renderInlineSwitch("silentStart", "Silent start", { disabled: true }), /checked/u);
});

test("icons exist for every kind a control asks for and an unknown kind is an error", () => {
  for (const kind of ["terminal", "info", "device-hub", "memory", "dns", "history"]) {
    assert.match(generalIconButton("x", kind, "Title", { tone: "warn", active: true }), /class="general-icon warn active"[\s\S]*<svg/u);
  }
  assert.throws(() => generalIconButton("x", "rocket", "Title"), /unknown General icon: rocket/u);
  for (const kind of ["check", "edit", "refresh", "folder", "send", "rules", "copy", "qr", "gear", "trash"]) {
    assert.match(profileMenuIcon(kind), /^<svg/u);
  }
  assert.throws(() => profileMenuIcon("toString"), /unknown profile menu icon/u);
});
