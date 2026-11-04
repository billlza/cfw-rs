// The Profiles page actions: importing, updating, editing and selecting profiles.
import { state } from "./state.js";
import { errorText, formatBytes } from "./text-format.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { isSubscriptionSource, readProfileSourceFile } from "./profile-import.js";
import { openProfileInspector } from "./profile-inspector.js";

export function createProfileActions({
  renderPage, renderGlassOverlays, scheduleRender, runProfileMenuAction, invokeProfileChange, loadProfilesSnapshot,
  selectProfileById, openCredentialSetup, resolveProfileSource, openProfileContextMenu, showInvalidProfileSource,
}) {
  const actions = {
    "update-profile-from-inspector": async () => {
      const id = state.profileInspector?.profile?.id ?? state.profileInspector?.id;
      if (!id) {
        appendLog("warning", "profile", t("No profile is open"));
      } else {
        await runProfileMenuAction("update", id);
        await openProfileInspector(id, "edit");
      }
      renderPage();
    },
    "import-profile": async () => {
      const input = document.querySelector("[data-profile-url]");
      const url = input?.value?.trim();
      if (!url) {
        appendLog("warning", "profile", t("A subscription URL or node link is required before import"));
      } else {
        const subscription = isSubscriptionSource(url);
        const result = subscription
          ? await invokeProfileChange("import_profile_url", { url, name: null, activate: true })
          : await invokeProfileChange("import_profile_text", { name: null, body: url });
        input.value = "";
        await loadProfilesSnapshot();
        appendLog("info", "profile", t("Profile imported: {name} ({value2})", { name: result.name, value2: formatBytes(result.bytes ?? 0) }));
        if (!subscription) {
          await selectProfileById(result.id);
        }
        await openCredentialSetup(result.id);
      }
      renderPage();
    },
    "paste-profile-url": async () => {
      const input = document.querySelector("[data-profile-url]");
      try {
        const text = await navigator.clipboard.readText();
        if (input) input.value = text.trim();
        appendLog("info", "profile", t("Profile URL pasted from clipboard"));
      } catch (_error) {
        appendLog("warning", "profile", t("Clipboard read was refused"));
      }
      renderPage();
    },
    "import-profile-file": async () => {
      const input = document.querySelector("[data-profile-file]");
      const file = input?.files?.[0];
      if (!file) {
        input?.click();
        return;
      }
      try {
        const body = await readProfileSourceFile(file);
        const result = await invokeProfileChange("import_profile_text", { name: file.name, body });
        await loadProfilesSnapshot();
        appendLog("info", "profile", t("Local profile imported: {name} ({value2})", { name: result.name, value2: formatBytes(result.bytes ?? 0) }));
        await selectProfileById(result.id);
        await openCredentialSetup(result.id);
      } finally {
        input.value = "";
      }
      renderPage();
    },
    "update-all-profiles": async (action) => {
      let updated = 0;
      let failed = 0;
      let local = 0;
      let cleanupPending = 0;
      // A profile list never carries a subscription URL, so each profile is read
      // once here, on this explicit user action, to find the remote ones.
      for (const profile of [...state.profiles]) {
        if (!(await resolveProfileSource(profile.id))) {
          local += 1;
          continue;
        }
        try {
          const result = await invokeProfileChange("update_profile", { id: profile.id });
          updated += 1;
          if (result.credential_cleanup_pending) {
            cleanupPending += 1;
            appendLog(
              "warning",
              "profile",
              t("{name} updated. Old credentials are retained for recovery.{value2}", { name: profile.name, value2: result.credential_cleanup_error ? t(" Cleanup: {error}", { error: result.credential_cleanup_error }) : "" }),
            );
          }
        } catch (error) {
          failed += 1;
          appendLog("error", "profile", t("Update failed for {name}: {error}", { name: profile.name, error: errorText(error) }));
        }
      }
      await loadProfilesSnapshot();
      appendLog(
        failed ? "error" : "info",
        "profile",
        t("Update All completed: {updated} updated{value2}{value3}{value4}", { updated: updated, value2: failed ? t(", {count} failed", { count: failed }) : "", value3: cleanupPending ? t(", {count} cleanup pending", { count: cleanupPending }) : "", value4: local ? t(", {count} without a subscription URL", { count: local }) : "" }),
      );
      renderPage();
    },
    "save-profile-editor": async () => {
      const editor = document.querySelector("[data-profile-editor]");
      const inspector = state.profileInspector;
      if (!editor || !inspector?.profile?.id) {
        appendLog("warning", "profile", t("No profile editor is open"));
      } else {
        const result = await invokeProfileChange("save_profile_text", { id: inspector.profile.id, expectedDigest: inspector.profile.digest, body: editor.value });
        await loadProfilesSnapshot();
        appendLog("info", "profile", t("Profile JSON saved: {value1}", { value1: formatBytes(result.bytes ?? 0) }));
        await openProfileInspector(result.id, "edit");
        await openCredentialSetup(result.id);
      }
      renderPage();
    },
    "close-profile-inspector": async () => {
      state.profileInspector = null;
      renderPage();
    },
  };

  function bindPage() {
    const profileFile = document.querySelector("[data-profile-file]");
    if (profileFile) {
      profileFile.addEventListener("change", () => {
        actions["import-profile-file"]().catch((error) => {
          appendLog("error", "profile", errorText(error));
          renderPage();
        });
      });
    }

    document.querySelectorAll("[data-profile-card]").forEach((card) => {
      card.addEventListener("click", async (event) => {
        // CFW: clicking the card selects it. Ignore clicks on action buttons/icons.
        if (event.target.closest("button, a, input, textarea, select")) return;
        const id = card.dataset.profileCard;
        if (!id) return;
        try {
          await selectProfileById(id);
        } catch (_error) {
          // selectProfileById already logged
        }
        renderPage();
      });
      card.addEventListener("contextmenu", (event) => {
        event.preventDefault();
        event.stopPropagation();
        openProfileContextMenu(card.dataset.profileCard, event.clientX, event.clientY);
      });
    });

    document.querySelectorAll("[data-profile-action]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        const action = event.currentTarget.dataset.profileAction;
        const id = event.currentTarget.dataset.profileId;
        try {
          await openProfileInspector(id, action);
          appendLog("info", "profile", t("{action} opened for {id}", { action: action, id: id }));
        } catch (error) {
          appendLog("error", "profile", t("{action} failed for {id}: {error}", { action: action, id: id, error: errorText(error) }));
        }
        renderPage();
      });
    });

    document.querySelectorAll("[data-invalid-profile-action]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.stopPropagation();
        const action = event.currentTarget.dataset.invalidProfileAction;
        const id = event.currentTarget.dataset.profileId;
        switch (action) {
          case "delete":
            state.glassDialog = { kind: "delete-invalid", id };
            renderGlassOverlays();
            return;
          case "show-source-url": {
            const name = state.invalidProfiles.find((item) => item.id === id)?.name ?? id;
            try {
              await showInvalidProfileSource(id);
            } catch (error) {
              appendLog("error", "profile", t("Could not read the subscription URL of {name}: {error}", { name: name, error: errorText(error) }));
            }
            renderPage();
            return;
          }
          default:
            appendLog("error", "profile", t("unknown profile menu action: {action}", { action: action }));
        }
      });
    });
  }

  async function importProfileFromPath(path) {
    try {
      const result = await invokeProfileChange("import_profile_file", { path, name: null, activate: true });
      await loadProfilesSnapshot();
      appendLog("info", "profile", t("Dropped profile imported: {name} ({value2})", { name: result.name, value2: formatBytes(result.bytes ?? 0) }));
      await openCredentialSetup(result.id);
      scheduleRender();
    } catch (error) {
      appendLog("error", "profile", t("Drag-drop import failed: {error}", { error: errorText(error) }));
    }
  }

  return { actions, bindPage, importProfileFromPath };
}
