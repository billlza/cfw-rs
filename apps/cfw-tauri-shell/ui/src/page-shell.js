// The page shell: the navigation, the page and its overlays, the status bar,
// and the frame scheduling that renders them.
import { PAGES, primaryNavIds, state, runtime, pageById } from "./state.js";
import { escapeHtml, formatRate, formatRuntime } from "./text-format.js";
import { t } from "./i18n.js";
import { navIcon } from "./nav-icons.js";
import { focusProfileEditorSection } from "./profile-inspector.js";

export function createPageShell({
  editingRender, replacePageMarkup, windowGlass, nativeGeneralSwitches, renderGlassOverlays, bindPageEvents, pageRenderers,
}) {
  const declaredPageIds = PAGES.map(({ id }) => id).sort();
  const rendererPageIds = Object.keys(pageRenderers).sort();
  if (
    declaredPageIds.length !== rendererPageIds.length
    || declaredPageIds.some((id, index) => id !== rendererPageIds[index])
  ) {
    throw new TypeError("renderer page implementations must exactly match the shared page contract");
  }

  let glassResizeQueued = false;

  /// A live resize fires many events per second; the glass follows once per
  /// frame, and the resized page measures itself again.
  function followWindowResize() {
    if (glassResizeQueued) return;
    glassResizeQueued = true;
    requestAnimationFrame(() => {
      glassResizeQueued = false;
      windowGlass.refresh();
    });
  }

  function renderNav() {
    const nav = document.getElementById("nav");
    nav.innerHTML = PAGES
      .filter((page) => primaryNavIds.has(page.id))
      .map((page, index) => {
        const active = page.id === state.activePage ? " active" : "";
        return `
        <button class="nav-item${active}" data-page="${escapeHtml(page.id)}"${active ? ' aria-current="page"' : ""}>
          <span>${index + 1}</span>
          ${navIcon(page.id)}
          <b>${escapeHtml(t(page.title))}</b>
        </button>
      `;
      })
      .join("");
  }

  function renderPage() {
    editingRender.render([
      state.activePage, state.glassDialog, state.runtimeSettingsDialog,
      state.automationDialog, state.profileInspector,
    ], renderPageContent);
  }

  function renderPageContent() {
    nativeGeneralSwitches.beforeRender();
    const page = pageById(state.activePage);
    const renderer = pageRenderers[page.id];
    if (typeof renderer !== "function") {
      throw new TypeError(`renderer is unavailable for page ${page.id}`);
    }
    document.title = "";
    const productName = document.getElementById("product-name");
    if (productName) productName.textContent = state.payload.product.name;
    const statusTitle = document.getElementById("status-title");
    if (statusTitle) statusTitle.textContent = state.mode ? t("{title} - {mode} Mode", { title: t(page.title), mode: t(state.mode) }) : t(page.title);
    document.getElementById("page-title").textContent = t(page.title);
    document.getElementById("page-summary").textContent = t(page.summary);
    const running = state.engine.active;
    const sidebarStatus = document.getElementById("sidebar-status");
    if (sidebarStatus) sidebarStatus.textContent = running ? t("Connected") : t("Disconnected");
    const sidebarDot = document.getElementById("sidebar-status-dot");
    if (sidebarDot) sidebarDot.className = running ? "on" : "";
    updateStatusBar();

    renderNav();
    replacePageMarkup(document.getElementById("page"), renderer(), [page.id]);
    bindPageEvents();
    renderGlassOverlays();
    nativeGeneralSwitches.refresh();
    windowGlass.refresh();
    if (state.profileInspector?.mode === "edit" && state.profileInspector.focusKey) {
      requestAnimationFrame(() => focusProfileEditorSection(state.profileInspector.focusKey));
    }
  }

  function updateStatusBar() {
    const up = document.getElementById("upload-rate");
    const down = document.getElementById("download-rate");
    const runtime = document.getElementById("runtime-value");
    const progress = document.getElementById("traffic-progress");
    if (up) {
      const value = formatRate(state.traffic.upload);
      if (up.textContent !== value) up.textContent = value;
    }
    if (down) {
      const value = formatRate(state.traffic.download);
      if (down.textContent !== value) down.textContent = value;
    }
    if (runtime) {
      const value = formatRuntime(state.traffic.runtimeSeconds);
      if (runtime.textContent !== value) runtime.textContent = value;
    }
    if (progress) {
      const total = Math.min(100, Math.max(0, (state.traffic.upload + state.traffic.download) * 4));
      const width = `${total}%`;
      if (progress.style.width !== width) progress.style.width = width;
    }
  }

  function scheduleRender() {
    if (runtime.renderFrame !== null) return;
    runtime.renderFrame = window.requestAnimationFrame(() => {
      runtime.renderFrame = null;
      runtime.connectionRowEls = null;
      renderPage();
    });
  }

  /// The runtime counter of the status bar advances once a second.
  function startStatusClock() {
    window.setInterval(() => {
      if (state.engine.active) {
        if (!state.engineStartedAt) state.engineStartedAt = Date.now();
        state.traffic.runtimeSeconds = Math.floor((Date.now() - state.engineStartedAt) / 1000);
      } else {
        state.engineStartedAt = null;
        state.traffic.runtimeSeconds = 0;
      }
      updateStatusBar();
    }, 1000);
  }

  return { followWindowResize, renderPage, updateStatusBar, scheduleRender, startStatusClock };
}
