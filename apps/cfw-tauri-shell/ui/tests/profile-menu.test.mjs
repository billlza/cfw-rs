import { dom, element, host, settle, spy } from "./support/fake-host.mjs";
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { state } from "../src/state.js";
import { createProfileMenu } from "../src/profile-menu.js";

const WORK = { id: "work", name: "Work", active: false, sourceUrl: "https://example.test/sub", updated: "now" };
const LOCAL = { id: "local", name: "Local", active: true, sourceUrl: null, updated: "now" };

function deps() {
  return {
    renderPage: spy(),
    renderGlassOverlays: spy(),
    resolveProfileSource: spy(async () => undefined),
    selectProfileById: spy(async () => true),
    invokeProfileChange: spy(async () => ({ name: "Work" })),
    loadProfilesSnapshot: spy(async () => true),
    openCredentialSetup: spy(async () => undefined),
  };
}

function engineOff() {
  state.engine = { ...state.engine, state: "Off", desiredMode: "off", active: false };
}

beforeEach(() => {
  host.reset();
  dom.reset();
  state.payload = { product: { operating_system: "macos" }, native_ui: { profile_menu: false } };
  state.profiles = [structuredClone(WORK), structuredClone(LOCAL)];
  state.profileContextMenu = null;
  state.glassDialog = null;
  state.runtimeSettingsDialog = null;
  state.automationDialog = null;
  state.activePage = "profiles";
  state.logs = [];
  engineOff();
  document.documentElement.dataset.theme = "light";
});

const lastLog = () => state.logs[0];

test("the in-page menu lists every item and states why an item is unavailable", () => {
  const menu = createProfileMenu(deps());
  assert.equal(menu.renderInPageMenu(), "", "no menu without a context");
  state.profileContextMenu = { id: "local", x: 10.4, y: 20.6 };
  const html = menu.renderInPageMenu();
  assert.match(html, /style="left:10px;top:21px"/u);
  for (const id of ["edit", "edit-external", "update", "reveal", "outbounds", "route", "copy", "qrcode",
    "credentials", "settings", "delete"]) {
    assert.match(html, new RegExp(`data-profile-menu="${id}"`, "u"));
  }
  assert.doesNotMatch(html, /data-profile-menu="select"/u, "the active profile offers no Select");
  state.profileContextMenu = { id: "work", x: 0, y: 0 };
  assert.match(menu.renderInPageMenu(), /data-profile-menu="select"/u, "another profile can be selected");
  state.profileContextMenu = { id: "local", x: 10.4, y: 20.6 };
  assert.match(html, /data-profile-menu="update"[^>]*disabled title=/u, "a local profile has no subscription to update");
  assert.match(html, /glass-menu-item danger" data-profile-menu="delete"/u);
  state.profileContextMenu = { id: "missing", x: 0, y: 0 };
  assert.equal(menu.renderInPageMenu(), "", "a vanished profile has no menu");
  state.payload.native_ui.profile_menu = true;
  state.profileContextMenu = { id: "work", x: 0, y: 0 };
  assert.equal(menu.renderInPageMenu(), "", "the native menu replaces the page menu");
});

test("credentials need a stopped core and say so", () => {
  const menu = createProfileMenu(deps());
  state.engine = { ...state.engine, state: "Running", desiredMode: "system_proxy", active: true };
  state.profileContextMenu = { id: "work", x: 0, y: 0 };
  assert.match(menu.renderInPageMenu(), /data-profile-menu="credentials"[^>]*disabled title="Stop the core/u);
});

test("the in-page menu stays inside the window and shows its more marker only while items are hidden", async () => {
  const menu = createProfileMenu(deps());
  menu.positionGlassMenu();
  const scroll = element("div", { scrollHeight: 400, clientHeight: 200, scrollTop: 0 });
  const more = element("div");
  const glass = element("div", { rect: { width: 300, height: 500 }, children: {
    "[data-glass-menu-scroll]": scroll, "[data-glass-menu-more]": more,
  } });
  dom.set(".glass-menu", glass);
  menu.positionGlassMenu();
  assert.equal(glass.style.left, "", "no context, no positioning");
  state.profileContextMenu = { id: "work", x: 800, y: 600 };
  menu.positionGlassMenu();
  assert.equal(glass.style.left, `${900 - 300 - 10}px`);
  assert.equal(glass.style.top, `${700 - 500 - 10}px`, "the menu moves up to fit");
  glass.rect = { width: 1000, height: 800 };
  menu.positionGlassMenu();
  assert.equal(glass.style.left, "10px", "a menu wider than the window starts at the padding");
  assert.equal(glass.style.top, "10px", "a menu taller than the window starts at the padding");
  glass.rect = { width: 300, height: 500 };
  assert.equal(more.hidden, false, "overflowing items are announced");
  scroll.scrollTop = 200;
  await scroll.fire("scroll");
  assert.equal(more.hidden, true, "the end of the list hides the marker");
  state.profileContextMenu = { id: "work", x: 15, y: 25 };
  glass.rect = { width: 100, height: 100 };
  menu.positionGlassMenu();
  assert.equal(glass.style.left, "15px");
  assert.equal(glass.style.top, "25px");
});

test("an in-page menu item closes the menu, runs its action and reports a failure", async () => {
  const d = deps();
  const menu = createProfileMenu(d);
  const copy = element("button", { dataset: { profileMenu: "copy", profileId: "work" } });
  const broken = element("button", { dataset: { profileMenu: "update", profileId: "missing" } });
  dom.setAll("[data-profile-menu]", [copy, broken]);
  menu.bindInPageMenu();
  state.profileContextMenu = { id: "work", x: 0, y: 0 };
  await copy.fire("click");
  assert.equal(state.profileContextMenu, null);
  assert.deepEqual(state.glassDialog, { kind: "copy", id: "work" });
  assert.equal(d.renderPage.count(), 1);
  await broken.fire("click");
  assert.match(lastLog().message, /update failed: profile not found: missing/u);
  assert.equal(d.renderPage.count(), 2);
});

test("each profile menu action does exactly its own work", async () => {
  const d = deps();
  const menu = createProfileMenu(d);
  host.respond("read_profile_text", ({ id }) => ({ id, name: "Work", body: "{}", digest: "d" }));
  host.respond("profile_qrcode_svg", "<svg/>");
  host.respond("open_profile_externally", null);
  host.respond("reveal_profile", null);

  await menu.runProfileMenuAction("select", "work");
  assert.deepEqual(d.selectProfileById.calls, [["work"]]);

  for (const [action, focus] of [["edit", null], ["outbounds", "outbounds"], ["route", "route"]]) {
    await menu.runProfileMenuAction(action, "work");
    assert.deepEqual(state.profileInspector, { id: "work", mode: "edit", profile: { id: "work", name: "Work", body: "{}", digest: "d" }, focusKey: focus });
    assert.match(lastLog().message, new RegExp(`${action} .*editor opened for Work`, "u"));
  }
  await menu.runProfileMenuAction("qrcode", "work");
  assert.equal(state.profileInspector.svg, "<svg/>");
  assert.match(lastLog().message, /QRCode opened for Work/u);

  await menu.runProfileMenuAction("edit-external", "work");
  assert.deepEqual(host.argsOf("open_profile_externally"), [{ id: "work" }]);
  await menu.runProfileMenuAction("reveal", "work");
  assert.deepEqual(host.argsOf("reveal_profile"), [{ id: "work" }]);
  assert.match(lastLog().message, /Show in folder: Work/u);

  for (const kind of ["copy", "settings", "delete"]) {
    const before = d.renderGlassOverlays.count();
    await menu.runProfileMenuAction(kind, "work");
    assert.deepEqual(state.glassDialog, { kind, id: "work" });
    assert.equal(d.renderGlassOverlays.count(), before + 1);
  }
  await menu.runProfileMenuAction("credentials", "work");
  assert.deepEqual(d.openCredentialSetup.calls, [["work"]]);

  await assert.rejects(() => menu.runProfileMenuAction("explode", "work"), /unknown profile menu action: explode/u);
  await assert.rejects(() => menu.runProfileMenuAction("edit", "missing"), /profile not found: missing/u);
});

test("an update reports retained credentials and their cleanup error", async () => {
  const d = deps();
  const menu = createProfileMenu(d);
  d.invokeProfileChange = spy(async () => ({ name: "Work" }));
  await createProfileMenu(d).runProfileMenuAction("update", "work");
  assert.deepEqual(d.invokeProfileChange.calls, [["update_profile", { id: "work" }]]);
  assert.equal(d.loadProfilesSnapshot.count(), 1);
  assert.match(lastLog().message, /Work subscription updated/u);

  d.invokeProfileChange = spy(async () => ({ name: "Work", credential_cleanup_pending: true }));
  await createProfileMenu(d).runProfileMenuAction("update", "work");
  assert.equal(lastLog().level, "warning");
  assert.doesNotMatch(lastLog().message, /Cleanup:/u);

  d.invokeProfileChange = spy(async () => ({ name: "Work", credential_cleanup_pending: true, credential_cleanup_error: "vault busy" }));
  await createProfileMenu(d).runProfileMenuAction("update", "work");
  assert.match(lastLog().message, /Cleanup: vault busy/u);
  void menu;
});

test("a closed or disabled native menu is not dismissed through the host", async () => {
  const menu = createProfileMenu(deps());
  menu.dismissNativeProfileMenu();
  await settle();
  assert.deepEqual(host.commands(), []);
  state.payload.native_ui.profile_menu = true;
  menu.dismissNativeProfileMenu();
  await settle();
  assert.deepEqual(host.commands(), [], "no presented request, nothing to close");
});

function nativeMenu(d = deps()) {
  state.payload.native_ui.profile_menu = true;
  return { d, menu: createProfileMenu(d) };
}

test("the native menu presents the profile's items and then reads its subscription URL", async () => {
  const { d, menu } = nativeMenu();
  host.respond("present_native_profile_menu", true);
  await menu.openProfileContextMenu("work", 120, 80);
  const [{ request, completion }] = host.argsOf("present_native_profile_menu");
  assert.equal(request.revision, 1);
  assert.equal(request.locale.length > 0, true);
  assert.equal(request.appearance, "light");
  assert.deepEqual(request.point, { x: 120, y: 80, viewportWidth: 900, viewportHeight: 700 });
  assert.ok(request.items.some((item) => item.id === "copy"));
  assert.ok(completion && typeof completion.id === "number", "results return on a channel");
  assert.equal(state.profileContextMenu.ready, true);
  assert.deepEqual(d.resolveProfileSource.calls, [["work"]]);
  assert.equal(d.renderGlassOverlays.count(), 1);
});

test("a native menu for a vanished profile is not presented", async () => {
  const { menu } = nativeMenu();
  await menu.openProfileContextMenu("missing", 0, 0);
  assert.equal(state.profileContextMenu, null);
  assert.deepEqual(host.commands(), []);
});

test("a refused native presentation clears the menu and is reported", async () => {
  const { d, menu } = nativeMenu();
  host.respond("present_native_profile_menu", new Error("panel unavailable"));
  await menu.openProfileContextMenu("work", 0, 0);
  assert.equal(state.profileContextMenu, null);
  assert.match(lastLog().message, /Profiles failed: panel unavailable/u);
  assert.equal(d.resolveProfileSource.count(), 0);
});

test("a native menu replaced while it was presented does not read its source", async () => {
  const { d, menu } = nativeMenu();
  host.respond("present_native_profile_menu", () => {
    state.profileContextMenu = { id: "local" };
    return true;
  });
  host.respond("dismiss_native_profile_menu", true);
  await menu.openProfileContextMenu("work", 0, 0);
  assert.equal(d.resolveProfileSource.count(), 0);
});

async function presented() {
  const { d, menu } = nativeMenu();
  host.respond("present_native_profile_menu", true);
  await menu.openProfileContextMenu("work", 0, 0);
  const { request, completion } = host.argsOf("present_native_profile_menu").at(-1);
  return { d, menu, request, completion, context: state.profileContextMenu };
}

test("a native selection runs the chosen action once", async () => {
  const { d, request, completion } = await presented();
  host.deliver(completion, { requestId: request.requestId, action: "copy", error: null });
  await settle();
  await settle();
  assert.deepEqual(state.glassDialog, { kind: "copy", id: "work" });
  assert.equal(state.profileContextMenu, null);
  assert.equal(d.renderPage.count(), 1);
});

test("a native menu reports its error, ignores a dismissal and refuses a stale action", async () => {
  let { d, request, completion } = await presented();
  host.deliver(completion, { requestId: request.requestId, action: null, error: "panel crashed" });
  await settle();
  assert.match(lastLog().message, /Profiles failed: panel crashed/u);
  assert.equal(d.renderPage.count(), 1);

  ({ d, request, completion } = await presented());
  host.deliver(completion, { requestId: request.requestId, action: null, error: null });
  await settle();
  assert.equal(d.renderPage.count(), 0, "a dismissed menu changes nothing");

  ({ d, request, completion } = await presented());
  state.engine = { ...state.engine, state: "Running", desiredMode: "system_proxy", active: true };
  host.deliver(completion, { requestId: request.requestId, action: "credentials", error: null });
  await settle();
  assert.match(lastLog().message, /Stop the core/u, "an item that became unavailable is refused with its reason");
  assert.equal(d.openCredentialSetup.count(), 0);
  engineOff();

  ({ d, request, completion } = await presented());
  state.profiles = state.profiles.filter((profile) => profile.id !== "work");
  host.deliver(completion, { requestId: request.requestId, action: "copy", error: null });
  await settle();
  assert.match(lastLog().message, /no longer available/u);
});

test("a native action that fails is reported and the page still renders", async () => {
  const { d, request, completion } = await presented();
  d.openCredentialSetup.calls.length = 0;
  host.respond("open_profile_externally", new Error("no editor"));
  host.deliver(completion, { requestId: request.requestId, action: "edit-external", error: null });
  await settle();
  await settle();
  assert.match(lastLog().message, /Profiles failed: no editor/u);
  assert.equal(d.renderPage.count(), 1);
});

test("a native selection for a menu that is no longer open is ignored", async () => {
  const { d, request, completion } = await presented();
  state.profileContextMenu = { id: "other" };
  host.deliver(completion, { requestId: request.requestId, action: "copy", error: null });
  await settle();
  assert.equal(state.glassDialog, null);
  assert.equal(d.renderPage.count(), 0);
});

test("the native menu follows changes of locale or appearance and closes when its page goes away", async () => {
  const { menu, context } = await presented();
  host.respond("update_native_profile_menu", true);
  host.respond("dismiss_native_profile_menu", true);
  menu.syncNativeProfileMenu();
  await settle();
  assert.deepEqual(host.argsOf("update_native_profile_menu"), [], "an unchanged projection is not sent again");
  document.documentElement.dataset.theme = "dark";
  menu.syncNativeProfileMenu();
  await settle();
  const [{ request }] = host.argsOf("update_native_profile_menu");
  assert.equal(request.revision, 2);
  assert.equal(request.appearance, "dark");
  assert.equal(context.revision, 2);

  state.activePage = "general";
  menu.syncNativeProfileMenu();
  await settle();
  assert.equal(state.profileContextMenu, null);
  assert.ok(host.commands().includes("dismiss_native_profile_menu"));
});

test("a refused native menu update closes the menu and is reported", async () => {
  const { menu } = await presented();
  host.respond("update_native_profile_menu", new Error("stale panel"));
  host.respond("dismiss_native_profile_menu", true);
  document.documentElement.dataset.theme = "dark";
  menu.syncNativeProfileMenu();
  await settle();
  await settle();
  assert.equal(state.profileContextMenu, null);
  assert.match(lastLog().message, /Profiles failed: stale panel/u);
});

test("an unready native menu is not synchronised", async () => {
  const { menu } = nativeMenu();
  state.profileContextMenu = { id: "work", ready: false };
  menu.syncNativeProfileMenu();
  assert.deepEqual(host.commands(), []);
  state.profileContextMenu = null;
  menu.syncNativeProfileMenu();
  assert.deepEqual(host.commands(), []);
});

test("the in-page menu renders before and after the subscription URL is read", async () => {
  const d = deps();
  const menu = createProfileMenu(d);
  await menu.openProfileContextMenu("work", 5, 6);
  assert.deepEqual(state.profileContextMenu, { id: "work", x: 5, y: 6 });
  assert.equal(d.renderGlassOverlays.count(), 2);
  d.resolveProfileSource = spy(async () => { state.profileContextMenu = null; });
  await createProfileMenu(d).openProfileContextMenu("work", 5, 6);
  assert.equal(d.renderGlassOverlays.count(), 3, "a menu closed during the read is not rendered again");
});
