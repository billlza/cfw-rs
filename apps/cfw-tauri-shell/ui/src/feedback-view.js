// The About page: version, update status and how this build runs the network.
import { PAGES, state } from "./state.js";
import { escapeHtml } from "./text-format.js";
import { t } from "./i18n.js";
import { platformPresentation, platformStartupDesign } from "./platform-presentation.js";

export function renderFeedback() {
  const product = state.payload.product;
  const presentation = platformPresentation(product.operating_system);
  const version = product.version ?? "—";
  const update = state.updateInfo;
  const updateLine = update?.available && update?.version
    ? t("New version available: v{value1} (current v{value2}).", { value1: escapeHtml(String(update.version)), value2: escapeHtml(String(update.current ?? version)) })
    : product.operating_system === "macos"
      ? t("Current build v{value1} — the menu bar Clash for Mac → Check for Update… also works.", { value1: escapeHtml(String(version)) })
      : t("Current build v{value1} — check for updates from the tray menu.", { value1: escapeHtml(String(version)) });
  const platform = state.platform;
  const startupDesign = platform ? platformStartupDesign(product.operating_system, platform) : null;
  return `
    <div class="feedback-layout">
      <section class="panel hero-panel">
        <div>
          <p class="label">${escapeHtml(t("About"))}</p>
          <h3>${escapeHtml(product.name)} v${escapeHtml(String(version))}${update?.available && update?.version ? ` → v${escapeHtml(String(update.version))}` : ""}</h3>
          <p class="muted">${escapeHtml(product.license)} · ${escapeHtml(product.architecture)} · ${presentation.name}${product.minimum_os_version === null ? "" : ` ${escapeHtml(t("{version} or later", { version: product.minimum_os_version }))}`}</p>
        </div>
        <span class="badge">${escapeHtml(product.operating_system === "macos" ? t("ARM64 macOS only") : `${presentation.name} ${product.architecture}`)}</span>
      </section>

      <section class="panel">
        <p class="label">${escapeHtml(t("Updates"))}</p>
        <h3>${escapeHtml(t("Check for Updates"))}</h3>
        <p class="muted">${updateLine}</p>
        <div class="toolbar-actions">
          <button class="button" data-action="check-for-updates">${escapeHtml(t("Check for Updates"))}</button>
        </div>
      </section>

      <section class="panel">
        <p class="label">${escapeHtml(t("Architecture"))}</p>
        <h3>${escapeHtml(t("How this build runs the network"))}</h3>
        ${platform ? `
          <dl class="ports-list feedback-list">
            <div><dt>${escapeHtml(t("system proxy"))}</dt><dd>${escapeHtml(t(platform.system_proxy_strategy ?? ""))}</dd></div>
            <div><dt>${escapeHtml(t("tunnel"))}</dt><dd>${escapeHtml(t(platform.tun_strategy ?? ""))}</dd></div>
            <div><dt>${escapeHtml(t("helper"))}</dt><dd>${escapeHtml(t(platform.helper_strategy ?? ""))}</dd></div>
            <div><dt>${escapeHtml(t(startupDesign.label))}</dt><dd>${escapeHtml(t(startupDesign.value))}</dd></div>
          </dl>
        ` : `<p class="muted">${escapeHtml(t("Platform design is unavailable."))}</p>`}
      </section>

      <section class="panel">
        <p class="label">${escapeHtml(t("Dashboard"))}</p>
        <h3>${escapeHtml(t("Layout reference"))}</h3>
        <dl class="ports-list feedback-list">
          <div><dt>${escapeHtml(t("window"))}</dt><dd>${escapeHtml(t("850 x 603 minimum baseline"))}</dd></div>
          <div><dt>${escapeHtml(t("pages"))}</dt><dd>${escapeHtml(PAGES.map((page) => page.id).join(" / "))}</dd></div>
        </dl>
      </section>
    </div>
  `;
}
