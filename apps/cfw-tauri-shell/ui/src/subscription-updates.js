// Subscriptions refreshed in the background: the interval the user chose,
// what the last attempt left beside each profile, and what the host reports.
import { state } from "./state.js";
import { errorText, escapeHtml, redactDiagnosticText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { engineIsOff } from "./engine-identity.js";

/// The intervals the host stores, under the names it stores them by.
export const UPDATE_INTERVAL_OPTIONS = Object.freeze([
  { value: "off", label: "Off" },
  { value: "six_hours", label: "Every 6 hours" },
  { value: "twelve_hours", label: "Every 12 hours" },
  { value: "daily", label: "Every day" },
  { value: "weekly", label: "Every week" },
]);

const isText = (value) => typeof value === "string" && value !== "";

/// The interval and, by profile id, what the last attempt left. A report of
/// any other shape is refused whole.
export function subscriptionUpdatesFrom(report) {
  if (!UPDATE_INTERVAL_OPTIONS.some(({ value }) => value === report?.interval) || !Array.isArray(report.profiles)) {
    throw new TypeError("subscription update report is malformed");
  }
  const notes = new Map();
  for (const profile of report.profiles) {
    if (!isText(profile?.id)) throw new TypeError("subscription update report is malformed");
    if (profile.state === "waiting") {
      notes.set(profile.id, { state: "waiting" });
    } else if (profile.state === "failed" && typeof profile.error === "string") {
      notes.set(profile.id, { state: "failed", error: redactDiagnosticText(profile.error) });
    } else {
      throw new TypeError("subscription update report is malformed");
    }
  }
  return { interval: report.interval, notes };
}

/// The profiles a look saved again.
function savedAgainFrom(report) {
  if (!Array.isArray(report?.updated)) throw new TypeError("subscription update report is malformed");
  for (const profile of report.updated) {
    if (!isText(profile?.id) || !isText(profile.name)
      || !Array.isArray(profile.reset_proxy_groups) || !profile.reset_proxy_groups.every(isText)) {
      throw new TypeError("subscription update report is malformed");
    }
  }
  return report.updated;
}

/// What a background update left beside a profile's card: a change to the
/// running profile that waits to be applied, or the reason an update failed.
export function renderSubscriptionUpdateNote(profile) {
  const note = state.subscriptionUpdates.notes.get(profile.id);
  if (!note) return "";
  if (note.state === "failed") {
    return `<p class="profile-card-update failed" role="note">${escapeHtml(t("Automatic update failed: {error}", { error: note.error }))}</p>`;
  }
  // A change that was found while the core ran this profile restarts the
  // core only for as long as the core still runs it.
  const restarts = profile.active && !engineIsOff();
  const applying = state.subscriptionUpdates.applying.has(profile.id);
  return `
    <p class="profile-card-update" role="note">${escapeHtml(t(restarts ? "New subscription content is available. Applying it restarts the core." : "New subscription content is available."))}</p>
    <button class="profile-card-apply" data-profile-update="${escapeHtml(profile.id)}" ${applying ? "disabled" : ""}>${escapeHtml(t(applying ? "Applying…" : "Apply update"))}</button>
  `;
}

export function createSubscriptionUpdates({ renderPage, loadProfilesSnapshot, loadRuntimeProjection, runProfileMenuAction }) {
  function accept(report) {
    const { interval, notes } = subscriptionUpdatesFrom(report);
    state.subscriptionUpdates = { ...state.subscriptionUpdates, interval, notes, error: null };
  }

  /// Reads the interval and the notes from the host. A failed read is shown
  /// beside the setting, which stays disabled until a read succeeds.
  async function load() {
    // The migration handoff instance runs no background updates and refuses
    // the read.
    if (state.migrationHandoff) return;
    try {
      accept(await invoke("subscription_updates"));
    } catch (error) {
      state.subscriptionUpdates = { ...state.subscriptionUpdates, interval: "off", notes: new Map(), error: errorText(error) };
      appendLog("error", "settings", t("Automatic subscription updates are unavailable: {error}", { error: state.subscriptionUpdates.error }));
    }
  }

  /// The read a caller does not wait for: what it finds is rendered when it
  /// arrives.
  async function loadAndRender() {
    await load();
    renderPage();
  }

  async function chooseInterval(interval) {
    try {
      accept(await invoke("set_subscription_update_interval", { interval }));
      const { label } = UPDATE_INTERVAL_OPTIONS.find(({ value }) => value === state.subscriptionUpdates.interval);
      appendLog("info", "settings", t("Automatic subscription updates: {interval}", { interval: t(label) }));
    } catch (error) {
      appendLog("error", "settings", t("Automatic subscription updates were not changed: {error}", { error: errorText(error) }));
      await load();
    }
    renderPage();
  }

  /// The host looked for due subscriptions, or dropped a note after the user
  /// updated a profile: the notes changed, and some profiles were saved again.
  async function onChanged(event) {
    let savedAgain;
    try {
      savedAgain = savedAgainFrom(event.payload);
      accept(event.payload);
    } catch (error) {
      appendLog("error", "profile", t("Rejected an invalid subscription update report: {error}", { error: errorText(error) }));
      await load();
      renderPage();
      return;
    }
    for (const profile of savedAgain) {
      appendLog("info", "profile", t("{name} updated automatically", { name: profile.name }));
      if (profile.reset_proxy_groups.length) {
        appendLog("warning", "profile", t("Saved nodes were removed from these groups; the new defaults apply: {value1}", { value1: profile.reset_proxy_groups.join(", ") }));
      }
    }
    if (savedAgain.length) {
      await loadProfilesSnapshot();
      // The staged projection belongs to the selected profile's document.
      await loadRuntimeProjection();
    }
    renderPage();
  }

  /// Applies a waiting change the way the profile menu's Update does. The
  /// host then drops the note and reports it.
  async function applyWaiting(id) {
    const { applying } = state.subscriptionUpdates;
    if (applying.has(id)) return;
    applying.add(id);
    renderPage();
    try {
      await runProfileMenuAction("update", id);
    } catch (error) {
      appendLog("error", "profile", t("{action} failed: {error}", { action: t("Update"), error: errorText(error) }));
    } finally {
      applying.delete(id);
    }
    renderPage();
  }

  function bindPage() {
    document.querySelectorAll("[data-subscription-update-interval]").forEach((select) => {
      select.addEventListener("change", () => chooseInterval(select.value));
    });
    document.querySelectorAll("[data-profile-update]").forEach((button) => {
      button.addEventListener("click", () => applyWaiting(button.dataset.profileUpdate));
    });
  }

  return { load, loadAndRender, onChanged, bindPage };
}
