import { state } from "./state.js";
import { escapeHtml } from "./text-format.js";
import { t } from "./i18n.js";
import { clearCutoverReceipt, cutoverReceiptIsCurrent, legacyMaintenanceRoute } from "./migration.js";

/// Optional maintenance for older Clash for Mac installations.
///
/// Settings exposes the controlled restart into the `--migration-handoff`
/// instance. Existing unfinished transactions keep their recovery surface.
/// Destructive actions retain their explicit preparation and confirmation.
export function renderMigrationBanner() {
  const retirement = state.retirement;
  if (!retirement || typeof retirement.state !== "string") return "";
  const route = legacyMaintenanceRoute(
    retirement, state.migrationHandoff, state.legacyMaintenanceOpen,
  );
  if (route === "none") return "";
  const close = state.legacyMaintenanceOpen && !state.migrationHandoff
    && legacyMaintenanceRoute(retirement, false) === "none"
    ? `<button type="button" class="cfw-text-button" data-action="close-legacy-maintenance">${escapeHtml(t("Close maintenance"))}</button>`
    : "";
  if (route === "complete") {
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>${escapeHtml(t("Legacy CFM maintenance is complete"))}</strong>
          <small>${escapeHtml(t("No legacy cleanup is pending."))}</small>
          ${close}
        </div>
      </div>
    `;
  }
  let cutover = state.cutover;
  if (cutover.receiptId && !cutoverReceiptIsCurrent(cutover)) {
    state.cutover = clearCutoverReceipt(cutover, {
      message: t("The cutover preparation expired. Prepare the replacement again."),
    });
    cutover = state.cutover;
  }

  if (route === "unverifiable") {
    return `
      <div class="cfw-migration-banner cfw-migration-unverifiable" role="alert">
        <div class="cfw-migration-copy">
          <strong>${escapeHtml(t("Legacy CFM maintenance state cannot be verified"))}</strong>
          <small>${escapeHtml(retirement.message ?? t("The legacy operation state could not be read. Reload before requesting maintenance."))}</small>
        </div>
      </div>
    `;
  }

  if (route === "busy") {
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>${escapeHtml(t("Legacy CFM maintenance is in progress"))}</strong>
          <small>${escapeHtml(t("The confirmed legacy operation must finish before another network start."))}</small>
        </div>
      </div>
    `;
  }

  if (route === "launch_prepare" || route === "launch_recovery") {
    const recovery = route === "launch_recovery";
    const handoffStatus = state.migrationHandoffStatus;
    const starting = handoffStatus?.state === "in_progress";
    const failure = handoffStatus?.state === "failed" ? handoffStatus.message : null;
    const profileUnavailable = !recovery && state.profilesUnavailableReason;
    const selectedProfileMissing = !recovery
      && !profileUnavailable
      && !state.profiles.some((profile) => profile.active === true);
    const detail = starting
      ? "The signed maintenance session is starting. This dashboard closes after the new window is ready and the current CFM engine is safely Off."
      : recovery
        ? "Review and resume the previous legacy CFM operation in its signed maintenance session."
        : profileUnavailable
          ? t("Profile state could not be verified: {profileUnavailable}. Open Profiles and reload it before legacy maintenance.", { profileUnavailable: profileUnavailable })
          : selectedProfileMissing
            ? "Import and select a replacement profile on Profiles before retiring older CFM components. Normal networking uses the System Proxy and TUN switches."
            : t("Optional maintenance retires older Clash for Mac components and managed data. Opening its signed session stops the current CFM engine and closes this dashboard; retirement still requires a separate confirmation. Use the network switches for normal starts.");
    const button = starting
      ? t("Starting…")
      : failure
        ? (recovery ? t("Retry Recovery…") : t("Retry Maintenance…"))
        : (profileUnavailable || selectedProfileMissing)
          ? t("Open Profiles")
          : (recovery ? t("Open Recovery…") : t("Open Legacy Maintenance…"));
    const action = profileUnavailable || selectedProfileMissing
      ? "open-migration-profiles"
      : "begin-migration-handoff";
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>${starting ? t("Legacy CFM maintenance session is starting") : recovery ? t("Legacy CFM recovery") : t("Optional legacy CFM maintenance")}</strong>
          <small>${escapeHtml(detail)}</small>
          ${retirement.message ? `<small>${escapeHtml(retirement.message)}</small>` : ""}
          ${failure ? `<small>${escapeHtml(failure)}</small>` : ""}
          ${starting ? "" : close}
        </div>
        <button type="button" class="cfw-big-button" data-action="${action}" ${starting ? "disabled" : ""}>${button}</button>
      </div>
    `;
  }

  if (route === "recover") {
    return `
      <div class="cfw-migration-banner" role="status">
        <div class="cfw-migration-copy">
          <strong>${escapeHtml(t("Recover the legacy CFM operation"))}</strong>
          <small>${escapeHtml(retirement.message ?? t("The unfinished legacy transaction requires explicit recovery."))}</small>
          ${cutover.message ? `<small>${escapeHtml(cutover.message)}</small>` : ""}
        </div>
        <button type="button" class="cfw-big-button" data-action="recover-cutover" ${cutover.busy ? "disabled" : ""}>${cutover.busy ? "Recovering…" : t("Recover Replacement")}</button>
      </div>
    `;
  }

  const target = cutover.target;
  const targetLabel = target === "tunnel" ? t("TUN") : t("System Proxy");
  const ready = cutoverReceiptIsCurrent(cutover);
  const step = ready
    ? `
        <label class="cfw-migration-confirm">
          <input type="checkbox" data-cutover-confirm ${cutover.confirmedReceiptId === cutover.receiptId ? "checked" : ""} />
          <span>${escapeHtml(t("I understand this one-way cutover retires older CFM components and managed data and cannot be undone."))}</span>
        </label>
        <label class="cfw-migration-confirm">
          <input type="checkbox" data-cutover-dns-review ${cutover.dnsReviewedReceiptId === cutover.receiptId ? "checked" : ""} />
          <span>${escapeHtml(t("I have reviewed DNS for every active service in System Settings."))}</span>
        </label>
        <button type="button" class="cfw-big-button danger" data-action="confirm-cutover" ${cutover.busy ? "disabled" : ""}>${cutover.busy ? t("Migrating…") : t("Confirm one-way cutover to {value1}", { value1: escapeHtml(targetLabel) })}</button>
      `
    : `
        <button type="button" class="cfw-big-button" data-action="prepare-cutover" ${cutover.busy ? "disabled" : ""}>${cutover.busy ? "Preparing…" : t("Prepare cutover to {value1}", { value1: escapeHtml(targetLabel) })}</button>
      `;
  const approvalNote = cutover.awaitingApproval
    ? `<small>${escapeHtml(t("System Extension approval is required in System Settings. Approve it, then Prepare again."))}</small>`
    : "";
  return `
    <div class="cfw-migration-banner" role="status">
      <div class="cfw-migration-copy">
        <strong>${escapeHtml(t("Legacy CFM maintenance session"))}</strong>
        <small>${escapeHtml(t("This optional operation retires older Clash for Mac components and starts the selected replacement mode. Prepare validates that operation; retirement requires your explicit confirmation."))}</small>
        <label class="cfw-migration-target">
          <span>${escapeHtml(t("Replacement"))}</span>
          <select data-cutover-target ${ready || cutover.busy ? "disabled" : ""}>
            <option value="system_proxy" ${target === "system_proxy" ? "selected" : ""}>${escapeHtml(t("System Proxy"))}</option>
            <option value="tunnel" ${target === "tunnel" ? "selected" : ""}>${escapeHtml(t("TUN"))}</option>
          </select>
        </label>
        ${retirement.message ? `<small>${escapeHtml(retirement.message)}</small>` : ""}
        ${cutover.message ? `<small>${escapeHtml(cutover.message)}</small>` : ""}
        ${approvalNote}
      </div>
      ${step}
    </div>
  `;
}
