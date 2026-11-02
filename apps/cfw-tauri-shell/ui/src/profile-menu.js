// The profile context menu: its items, the native or in-page presentation,
// and the action each item runs.
import { Channel } from "@tauri-apps/api/core";
import { state } from "./state.js";
import { errorText, escapeHtml } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t, getLocale } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { engineIsOff } from "./engine-identity.js";
import { REASONS } from "./reasons.js";
import { profileMenuIcon } from "./controls.js";
import { profileMenuItems, nativeMenuItems, createNativeProfileMenu } from "./native-profile-menu.js";
import { openProfileInspector } from "./profile-inspector.js";

/// CFW profile context-menu items, in the 0.3.5 order and chrome.
///
/// `remoteOnly` items need the profile's subscription URL, which a profile list
/// deliberately never publishes. Opening the menu reads the single profile, so
/// the URL is known here; when that read fails the item is shown disabled with
/// the reason instead of being hidden.
const PROFILE_MENU_ACTIONS = [
  { id: "select", get label() { return t("Select"); }, icon: "check", needsInactive: true },
  { id: "edit", get label() { return t("Edit"); }, icon: "edit" },
  { id: "edit-external", get label() { return t("Edit externally"); }, icon: "edit" },
  { id: "update", get label() { return t("Update"); }, icon: "refresh", remoteOnly: true },
  { id: "reveal", get label() { return t("Show in folder"); }, icon: "folder" },
  { id: "outbounds", get label() { return t("Edit outbounds section"); }, icon: "send" },
  { id: "route", get label() { return t("Edit route section"); }, icon: "rules" },
  { id: "copy", get label() { return t("Copy"); }, icon: "copy" },
  { id: "qrcode", label: "QRCode", icon: "qr", remoteOnly: true },
  { id: "credentials", get label() { return t("Credentials"); }, icon: "gear", needsEngineOff: true },
  { id: "settings", get label() { return t("Settings"); }, icon: "gear" },
  { id: "delete", get label() { return t("Delete"); }, icon: "trash", danger: true },
];

export function createProfileMenu({ renderPage, renderGlassOverlays, resolveProfileSource, selectProfileById, invokeProfileChange, loadProfilesSnapshot, openCredentialSetup }) {
  const nativeProfileMenu = createNativeProfileMenu({ invoke, makeChannel: (handler) => new Channel(handler), onError: reportProfileMenuFailure });

  function nativeProfileMenuEnabled() { return state.payload?.native_ui?.profile_menu === true; }

  function reportProfileMenuFailure(error) {
    appendLog("error", "profile", t("{action} failed: {error}", { action: t("Profiles"), error: errorText(error) }));
  }

  function dismissNativeProfileMenu() {
    if (nativeProfileMenuEnabled()) void nativeProfileMenu.dismiss().catch(reportProfileMenuFailure);
  }

  function currentProfileMenuItems(profile) {
    return profileMenuItems(PROFILE_MENU_ACTIONS, profile, { engineOff: engineIsOff(), engineNotOffReason: REASONS.engineNotOff, t });
  }

  function nativeProfileMenuRequest(context, profile) {
    return { requestId: context.requestId, revision: context.revision, locale: getLocale(),
      appearance: document.documentElement.dataset.theme,
      moreLabel: t("scroll to view more"), point: context.point, items: nativeMenuItems(currentProfileMenuItems(profile)) };
  }

  async function acceptNativeProfileMenu(context, result) {
    if (state.profileContextMenu !== context) return;
    state.profileContextMenu = null;
    if (result.error) { reportProfileMenuFailure(result.error); renderPage(); return; }
    if (result.action === null) return;
    const profile = state.profiles.find((item) => item.id === context.id);
    const action = profile && currentProfileMenuItems(profile).find((item) => item.id === result.action);
    if (!action || action.reason) {
      reportProfileMenuFailure(action?.reason ?? "The profile action is no longer available");
      renderPage(); return;
    }
    try { await runProfileMenuAction(result.action, context.id); }
    catch (error) { reportProfileMenuFailure(error); }
    renderPage();
  }

  async function openProfileContextMenu(id, clientX, clientY) {
    state.glassDialog = null;
    const context = { id, x: clientX, y: clientY };
    state.profileContextMenu = context;
    if (nativeProfileMenuEnabled()) {
      const profile = state.profiles.find((item) => item.id === id);
      if (!profile) { state.profileContextMenu = null; return; }
      Object.assign(context, { requestId: crypto.randomUUID(), revision: 1, ready: false,
        point: { x: clientX, y: clientY, viewportWidth: window.innerWidth, viewportHeight: window.innerHeight } });
      try {
        const request = nativeProfileMenuRequest(context, profile);
        context.projection = JSON.stringify({ locale: request.locale, appearance: request.appearance, items: request.items });
        context.ready = await nativeProfileMenu.present(request, (result) => {
          void acceptNativeProfileMenu(context, result).catch(reportProfileMenuFailure);
        });
        if (state.profileContextMenu !== context) return;
        await resolveProfileSource(id);
        if (state.profileContextMenu === context) renderGlassOverlays();
      } catch (error) {
        if (state.profileContextMenu === context) {
          state.profileContextMenu = null;
          dismissNativeProfileMenu();
        }
        reportProfileMenuFailure(error);
      }
      return;
    }
    renderGlassOverlays();
    await resolveProfileSource(id);
    if (state.profileContextMenu === context) renderGlassOverlays();
  }

  function syncNativeProfileMenu() {
    const context = state.profileContextMenu;
    if (!context?.ready || !context.requestId) return;
    const profile = state.profiles.find((item) => item.id === context.id);
    if (!profile || state.activePage !== "profiles" || state.glassDialog || state.runtimeSettingsDialog || state.automationDialog) {
      dismissNativeProfileMenu();
      state.profileContextMenu = null;
      return;
    }
    const request = nativeProfileMenuRequest(context, profile);
    const projection = JSON.stringify({ locale: request.locale, appearance: request.appearance, items: request.items });
    if (projection === context.projection) return;
    context.projection = projection;
    request.revision = ++context.revision;
    void nativeProfileMenu.update(request).catch((error) => {
      if (state.profileContextMenu !== context) return;
      state.profileContextMenu = null;
      dismissNativeProfileMenu();
      reportProfileMenuFailure(error);
    });
  }

  async function runProfileMenuAction(action, id) {
    const profile = state.profiles.find((item) => item.id === id);
    if (!profile) throw new Error(t("profile not found: {id}", { id: id }));

    switch (action) {
      case "select":
        await selectProfileById(id);
        return;
      case "edit":
        await openProfileInspector(id, "edit");
        appendLog("info", "profile", t("edit editor opened for {name}", { name: profile.name }));
        return;
      case "outbounds":
        await openProfileInspector(id, "edit", "outbounds");
        appendLog("info", "profile", t("outbounds section editor opened for {name}", { name: profile.name }));
        return;
      case "route":
        await openProfileInspector(id, "edit", "route");
        appendLog("info", "profile", t("route section editor opened for {name}", { name: profile.name }));
        return;
      case "edit-external":
        await invoke("open_profile_externally", { id });
        appendLog("info", "profile", t("Opened {name} externally", { name: profile.name }));
        return;
      case "update": {
        const result = await invokeProfileChange("update_profile", { id });
        await loadProfilesSnapshot();
        appendLog("info", "profile", t("{name} subscription updated", { name: result.name }));
        if (result.credential_cleanup_pending) {
          appendLog(
            "warning",
            "profile",
            t("{name} updated. Old credentials are retained for recovery.{value2}", { name: result.name, value2: result.credential_cleanup_error ? t(" Cleanup: {error}", { error: result.credential_cleanup_error }) : "" }),
          );
        }
        return;
      }
      case "reveal":
        await invoke("reveal_profile", { id });
        appendLog("info", "profile", t("Show in folder: {name}", { name: profile.name }));
        return;
      case "copy":
        state.glassDialog = { kind: "copy", id };
        renderGlassOverlays();
        return;
      case "qrcode":
        await openProfileInspector(id, "qrcode");
        appendLog("info", "profile", t("QRCode opened for {name}", { name: profile.name }));
        return;
      case "credentials":
        await openCredentialSetup(id);
        return;
      case "settings":
        state.glassDialog = { kind: "settings", id };
        renderGlassOverlays();
        return;
      case "delete":
        // WKWebView often swallows window.confirm (always false) — use in-app glass dialog.
        state.glassDialog = { kind: "delete", id };
        renderGlassOverlays();
        return;
      default:
        throw new Error(t("unknown profile menu action: {action}", { action: action }));
    }
  }

  function renderInPageMenu() {
    if (state.profileContextMenu && !nativeProfileMenuEnabled()) {
      const profile = state.profiles.find((item) => item.id === state.profileContextMenu.id);
      if (profile) {
        const items = currentProfileMenuItems(profile);
        const menuHtml = items.map((action) => `
        <button type="button" class="glass-menu-item ${action.danger ? "danger" : ""}" data-profile-menu="${action.id}" data-profile-id="${escapeHtml(profile.id)}" ${action.reason ? `disabled title="${escapeHtml(action.reason)}"` : ""}>
          <span class="glass-menu-icon">${profileMenuIcon(action.icon)}</span>
          <span>${escapeHtml(action.label)}</span>
        </button>
      `).join("");
        return (`
        <div class="glass-menu-backdrop" data-glass-dismiss></div>
        <div class="glass-menu" role="menu" style="left:${Math.round(state.profileContextMenu.x)}px;top:${Math.round(state.profileContextMenu.y)}px">
          <div class="glass-menu-scroll" data-glass-menu-scroll>
            ${menuHtml}
          </div>
          <div class="glass-menu-more" data-glass-menu-more hidden>
            <span>${escapeHtml(t("scroll to view more"))}</span>
            <span aria-hidden="true">▾</span>
          </div>
        </div>
      `);
      }
    }
    return "";
  }

  function positionGlassMenu() {
    const menu = document.querySelector(".glass-menu");
    if (!menu || !state.profileContextMenu) return;
    const pad = 10;
    const rect = menu.getBoundingClientRect();
    let left = state.profileContextMenu.x;
    let top = state.profileContextMenu.y;
    if (left + rect.width > window.innerWidth - pad) left = Math.max(pad, window.innerWidth - rect.width - pad);
    if (top + rect.height > window.innerHeight - pad) top = Math.max(pad, window.innerHeight - rect.height - pad);
    menu.style.left = `${Math.round(left)}px`;
    menu.style.top = `${Math.round(top)}px`;

    const scroll = menu.querySelector("[data-glass-menu-scroll]");
    const more = menu.querySelector("[data-glass-menu-more]");
    if (scroll && more) {
      const updateMore = () => {
        const overflow = scroll.scrollHeight > scroll.clientHeight + 2;
        const atBottom = scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - 2;
        more.hidden = !overflow || atBottom;
      };
      scroll.addEventListener("scroll", updateMore, { passive: true });
      updateMore();
    }
  }

  function bindInPageMenu() {
    document.querySelectorAll("[data-profile-menu]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        const action = event.currentTarget.dataset.profileMenu;
        const id = event.currentTarget.dataset.profileId;
        state.profileContextMenu = null;
        renderGlassOverlays();
        try {
          await runProfileMenuAction(action, id);
        } catch (error) {
          appendLog("error", "profile", t("{action} failed: {error}", { action: action, error: errorText(error) }));
        }
        renderPage();
      });
    });
  }

  return {
    dismissNativeProfileMenu, nativeProfileMenuEnabled, openProfileContextMenu, runProfileMenuAction, syncNativeProfileMenu,
    renderInPageMenu, positionGlassMenu, bindInPageMenu,
  };
}
