// The dialogs that act on one profile: copy, edit its name and URL, delete,
// and show the subscription URL of an invalid profile.
import { state } from "./state.js";
import { escapeHtml, errorText } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";

export function createProfileDialogs({
  renderPage, renderGlassOverlays, closeGlassOverlays, closeGlassDialog, loadProfilesSnapshot, invokeProfileChange,
}) {
  /// A refused deletion keeps its dialog open and is reported in the log.
  async function confirmProfileDeletion(dialog, id) {
    const profile = state.profiles.find((item) => item.id === id)
      ?? state.invalidProfiles.find((item) => item.id === id);
    try {
      const deleted = await invoke("delete_profile", { id });
      await loadProfilesSnapshot();
      closeGlassDialog(dialog);
      appendLog(
        deleted ? "warning" : "info",
        "profile",
        deleted ? t("Profile deleted: {value1}", { value1: profile?.name ?? id }) : t("Profile already missing: {id}", { id: id }),
      );
    } catch (error) {
      appendLog("error", "profile", t("Delete failed: {error}", { error: errorText(error) }));
      // A deletion that cleared the selection may still have failed to remove
      // the profile; the list is re-read rather than assumed unchanged.
      await loadProfilesSnapshot();
    }
    renderPage();
  }

  /// The invalid subscription workaround imports its URL again. The URL is read
  /// on request and shown in a dialog whose Copy button writes the clipboard
  /// within its own click; it never reaches the list or the log.
  async function showInvalidProfileSource(id) {
    const profile = state.invalidProfiles.find((item) => item.id === id);
    if (!profile) throw new Error(t("profile not found: {id}", { id: id }));
    const url = await invoke("read_profile_source_url", { id });
    if (typeof url !== "string") throw new Error(t("{name} has no subscription URL", { name: profile.name }));
    state.glassDialog = { kind: "invalid-profile-source", id, payload: url };
    renderGlassOverlays();
  }

  function prompt(dialog, profile) {
    if (profile && dialog.kind === "delete") {
      return {
        title: t("Delete profile"),
        message: t("Delete “{name}”? This removes the managed profile from the repository.", { name: profile.name }),
        buttons: [
          { id: "cancel", title: t("No"), role: "cancel" },
          { id: "confirm", title: t("Yes"), role: "destructive", activate: () => confirmProfileDeletion(dialog, profile.id) },
        ],
      };
    }
    if (profile && dialog.kind === "delete-invalid") {
      return {
        title: t("Delete profile"),
        message: profile.selected
          ? t("Delete “{name}”? It is selected but fails validation; afterwards no profile is selected.", { name: profile.name })
          : t("Delete “{name}”? It fails validation and cannot be used.", { name: profile.name }),
        buttons: [
          { id: "cancel", title: t("No"), role: "cancel" },
          { id: "confirm", title: t("Yes"), role: "destructive", activate: () => confirmProfileDeletion(dialog, profile.id) },
        ],
      };
    }
    return null;
  }

  function renderCopyDialog(profile) {
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Copy profile"))}">
          <h3>${escapeHtml(t("Copy profile"))}</h3>
          <label>${escapeHtml(t("Name"))}<input data-glass-copy-name value="${escapeHtml(t("{name} copy", { name: profile.name }))}" /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Cancel"))}</button>
            <button type="button" class="glass-btn" data-glass-copy-confirm="${escapeHtml(profile.id)}">${escapeHtml(t("Copy"))}</button>
          </div>
        </div>
      `);
  }

  function renderSettingsDialog(profile) {
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Edit profile information"))}">
          <h3>${escapeHtml(t("Edit profile information"))}</h3>
          <label>${escapeHtml(t("Name"))}<input data-glass-settings-name value="${escapeHtml(profile.name)}" /></label>
          <label>URL<input data-glass-settings-url value="${escapeHtml(profile.sourceUrl ?? "")}" placeholder="https://..." /></label>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Cancel"))}</button>
            <button type="button" class="glass-btn" data-glass-settings-confirm="${escapeHtml(profile.id)}">${escapeHtml(t("Save"))}</button>
          </div>
        </div>
      `);
  }

  function renderDeleteDialog(profile, prompt) {
    const [cancel, confirm] = prompt.buttons;
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Delete profile"))}">
          <h3>${escapeHtml(prompt.title)}</h3>
          <p class="glass-dialog-copy">${escapeHtml(prompt.message)}</p>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(cancel.title)}</button>
            <button type="button" class="glass-btn danger" data-glass-delete-confirm="${escapeHtml(profile.id)}">${escapeHtml(confirm.title)}</button>
          </div>
        </div>
      `);
  }

  function renderInvalidSourceDialog(dialog, profile) {
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Subscription URL"))}">
          <h3>${escapeHtml(t("Subscription URL"))}</h3>
          <p class="glass-dialog-copy">${escapeHtml(t("Import this URL again to replace “{name}”, then delete the invalid profile.", { name: profile.name }))}</p>
          <pre class="glass-code">${escapeHtml(dialog.payload ?? "")}</pre>
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button>
            <button type="button" class="glass-btn" data-glass-copy-text>${escapeHtml(t("Copy"))}</button>
          </div>
        </div>
      `);
  }

  function render(dialog, profile, prompt) {
    if (!profile) return "";
    switch (dialog.kind) {
      case "copy": return renderCopyDialog(profile);
      case "settings": return renderSettingsDialog(profile);
      case "delete":
      case "delete-invalid": return renderDeleteDialog(profile, prompt);
      case "invalid-profile-source": return renderInvalidSourceDialog(dialog, profile);
      default: throw new TypeError(`profile dialog ${dialog.kind} is unknown`);
    }
  }

  function bind() {
    document.querySelectorAll("[data-glass-copy-confirm]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        const id = event.currentTarget.dataset.glassCopyConfirm;
        const name = document.querySelector("[data-glass-copy-name]")?.value?.trim();
        if (!name) return;
        try {
          const text = await invoke("read_profile_text", { id });
          const result = await invokeProfileChange("import_profile_text", { name, body: text.body });
          await loadProfilesSnapshot();
          closeGlassOverlays();
          appendLog("info", "profile", t("Copied profile to {name}; select it to make it active", { name: result.name }));
        } catch (error) {
          appendLog("error", "profile", t("Copy failed: {error}", { error: errorText(error) }));
        }
        renderPage();
      });
    });

    document.querySelectorAll("[data-glass-settings-confirm]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        const id = event.currentTarget.dataset.glassSettingsConfirm;
        const name = document.querySelector("[data-glass-settings-name]")?.value?.trim() ?? "";
        const url = document.querySelector("[data-glass-settings-url]")?.value?.trim() ?? "";
        try {
          await invoke("update_profile_info", { id, name, url });
          await loadProfilesSnapshot();
          closeGlassOverlays();
          appendLog("info", "profile", t("Profile settings saved: {name}", { name: name }));
        } catch (error) {
          appendLog("error", "profile", t("Settings failed: {error}", { error: errorText(error) }));
        }
        renderPage();
      });
    });

    document.querySelectorAll("[data-glass-delete-confirm]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        await confirmProfileDeletion(state.glassDialog, event.currentTarget.dataset.glassDeleteConfirm);
      });
    });
  }

  return {
    showInvalidProfileSource,
    dialogs: { kinds: ["copy", "settings", "delete", "delete-invalid", "invalid-profile-source"], prompt, render, bind },
  };
}
