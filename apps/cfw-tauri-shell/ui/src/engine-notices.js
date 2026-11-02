// Notices the General page shows while the background services are not
// answering or are being recovered.
import { runtime } from "./state.js";
import { escapeHtml } from "./text-format.js";
import { t } from "./i18n.js";

/// The core is leased and running as far as the host knows, but its last
/// status reads did not come back. The host keeps re-observing on its own.
export function renderObservationRecheckNotice(reason) {
  const detail = reason
    ? `<details class="cfw-notice-detail"><summary>${escapeHtml(t("Technical details"))}</summary><small>${escapeHtml(reason)}</small></details>`
    : "";
  return `
    <div class="cfw-row cfw-row-notice" role="status">
      <div class="cfw-row-left">
        <strong>${escapeHtml(t("Confirming the core's state"))}</strong>
        <span>${escapeHtml(t("The background services did not answer in time. The core and your network settings were left as they are; this notice clears by itself once they answer."))}</span>
        ${detail}
      </div>
      <div class="cfw-row-right"></div>
    </div>
  `;
}

/// What the General page shows while the host offers startup recovery: the
/// automatic retries in plain words, then the steps the user can take. The
/// host's own reason stays available as technical detail.
export function renderStartupRecoveryNotice(reason) {
  const recovery = runtime.startupRecovery;
  const detail = reason
    ? `<details class="cfw-notice-detail"><summary>${escapeHtml(t("Technical details"))}</summary><small>${escapeHtml(reason)}</small></details>`
    : "";
  if (!recovery.exhausted) {
    return `
      <div class="cfw-row cfw-row-notice" role="status">
        <div class="cfw-row-left">
          <strong>${escapeHtml(t("Background services are restarting"))}</strong>
          <span>${escapeHtml(t("This happens after an installation or update. The dashboard retries by itself in a few seconds."))}</span>
          ${detail}
        </div>
        <div class="cfw-row-right"></div>
      </div>
    `;
  }
  return `
    <div class="cfw-row cfw-row-notice cfw-row-notice-action" role="alert">
      <div class="cfw-row-left">
        <strong>${escapeHtml(t("Background services need your help"))}</strong>
        <ol>
          <li>${escapeHtml(t("Click “{button}” on the core row.", { button: t("Recover background services") }))}</li>
          <li>${escapeHtml(t("If macOS shows a “Background Items” notice, open System Settings → General → Login Items & Extensions and allow Clash for Mac."))}</li>
          <li>${escapeHtml(t("If it still fails, quit and reopen Clash for Mac."))}</li>
        </ol>
        ${detail}
      </div>
      <div class="cfw-row-right"></div>
    </div>
  `;
}
