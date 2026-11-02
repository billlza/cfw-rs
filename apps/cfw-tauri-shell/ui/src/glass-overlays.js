// The overlay layer above the page: the in-page profile menu, the dialogs of
// every feature, and the runtime and automation settings dialogs. A dialog
// that only asks or informs is shown by the native prompt panel when the host
// offers it.
import { state } from "./state.js";
import { escapeHtml, errorText, redactDiagnosticText } from "./text-format.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import { promptDialogFrame } from "./native-prompt-dialog.js";

export function createGlassOverlays({
  nativeGeneralSwitches, nativePromptDialog, runtimeSettingsUI, automationSettingsUI, replaceOverlayMarkup,
  profileMenu, providers,
}) {
  const infoDialog = {
    kinds: ["info"],
    prompt(dialog) {
      return {
        title: dialog.payload?.title ?? t("Info"),
        message: dialog.payload?.body ?? "",
        buttons: [{ id: "cancel", title: t("Close"), role: "cancel" }],
      };
    },
    render: renderInfoDialog,
    bind() {},
  };
  function renderInfoDialog(dialog, profile, prompt) {
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Info"))}">
          <h3>${escapeHtml(prompt.title)}</h3>
          <p class="glass-dialog-copy">${escapeHtml(prompt.message)}</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(prompt.buttons[0].title)}</button></div>
        </div>
      `);
  }

  const dialogProviders = [...providers, infoDialog];
  const providerByKind = new Map();
  for (const provider of dialogProviders) {
    for (const kind of provider.kinds) {
      if (providerByKind.has(kind)) throw new TypeError(`dialog ${kind} has two providers`);
      providerByKind.set(kind, provider);
    }
  }

  function overlayOpen() {
    return Boolean(state.profileContextMenu || state.glassDialog || state.runtimeSettingsDialog || state.automationDialog);
  }

  function closeGlassOverlays() {
    profileMenu.dismissNativeProfileMenu();
    runtimeSettingsUI.close();
    automationSettingsUI.close();
    state.profileContextMenu = null;
    state.glassDialog = null;
    renderGlassOverlays();
  }

  /// The profile a dialog acts on. Only deletion and showing its subscription
  /// URL may name an invalid profile.
  function dialogProfile(dialog) {
    if (!dialog.id) return null;
    const invalid = dialog.kind === "delete-invalid" || dialog.kind === "invalid-profile-source";
    const profiles = invalid ? state.invalidProfiles : state.profiles;
    return profiles.find((item) => item.id === dialog.id) ?? null;
  }

  /// The dialogs that only ask or inform, described once so the page markup and
  /// the native panel cannot drift apart. A button's `activate` is the confirm
  /// path its web button runs.
  function promptDialogContent(dialog, profile) {
    return providerByKind.get(dialog.kind)?.prompt?.(dialog, profile) ?? null;
  }

  async function activatePromptDialog(dialog, prompt, buttonId) {
    if (state.glassDialog !== dialog) return;
    const button = prompt.buttons.find((item) => item.id === buttonId);
    if (typeof button?.activate !== "function") throw new Error(`Prompt dialog button ${buttonId} has no action`);
    await button.activate();
  }

  /// Closes the dialog that started an action. The user may have dismissed it or
  /// opened something else while the action ran; that is left as it is.
  function closeGlassDialog(dialog) {
    if (state.glassDialog !== dialog) return;
    state.glassDialog = null;
    renderGlassOverlays();
  }

  function renderGlassOverlays() {
    // Dialogs also render independently of renderPageContent (for example,
    // network services). Invalidate native input before replacing any overlay.
    nativeGeneralSwitches.beforeRender();
    if (profileMenu.nativeProfileMenuEnabled()) profileMenu.syncNativeProfileMenu();
    const root = document.getElementById("glass-menu-root");
    if (!root) return;

    const parts = [];
    parts.push(profileMenu.renderInPageMenu());

    let nativePrompt = null;
    if (state.glassDialog) {
      const dialog = state.glassDialog;
      const profile = dialogProfile(dialog);
      const prompt = promptDialogContent(dialog, profile);
      nativePrompt = prompt && nativePromptDialog.enabled() ? promptDialogFrame(prompt) : null;
      if (nativePrompt) {
        const failure = nativePromptDialog.sync(dialog, nativePrompt, {
          onActivate: (buttonId) => activatePromptDialog(dialog, prompt, buttonId),
          onClose: () => { if (state.glassDialog === dialog) closeGlassOverlays(); },
          onChange: renderGlassOverlays,
        });
        // Keep the page backdrop and its dismissal under the native panel. A
        // refused presentation still says what the dialog had to say and states
        // the failure; it never offers the confirmation.
        parts.push(`<div class="glass-dialog-backdrop" data-glass-dismiss></div>${failure ? `
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(prompt.title)}">
          <h3>${escapeHtml(prompt.title)}</h3>
          <p class="glass-dialog-copy">${escapeHtml(prompt.message)}</p>
          <p class="glass-dialog-copy warning" role="alert">${escapeHtml(redactDiagnosticText(failure))}</p>
          <div class="glass-dialog-actions"><button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(prompt.buttons[0].title)}</button></div>
        </div>` : ""}`);
      } else {
        const provider = providerByKind.get(dialog.kind);
        if (!provider) throw new TypeError(`dialog ${dialog.kind} has no provider`);
        parts.push(provider.render(dialog, profile, prompt));
      }
    }
    if (!nativePrompt) nativePromptDialog.sync(null);

    parts.push(runtimeSettingsUI.renderDialog());
    parts.push(automationSettingsUI.renderDialog());
    replaceOverlayMarkup(root, parts.join(""),
      [state.profileContextMenu, state.glassDialog, state.runtimeSettingsDialog, state.automationDialog]);
    runtimeSettingsUI.bindDialog();
    automationSettingsUI.bindDialog();
    profileMenu.positionGlassMenu();
    bindGlassOverlayEvents();
    nativeGeneralSwitches.refresh();
  }

  function bindGlassOverlayEvents() {
    document.querySelectorAll("[data-glass-dismiss]").forEach((node) => {
      node.addEventListener("click", () => closeGlassOverlays());
    });

    profileMenu.bindInPageMenu();

    document.querySelectorAll("[data-glass-copy-text]").forEach((button) => {
      button.addEventListener("click", async () => {
        const textValue = state.glassDialog?.payload ?? document.querySelector(".glass-code")?.textContent ?? "";
        try {
          await navigator.clipboard.writeText(String(textValue));
          appendLog("info", "clipboard", t("Copied dialog text"));
        } catch (error) {
          appendLog("warning", "clipboard", errorText(error));
        }
      });
    });

    for (const provider of dialogProviders) provider.bind();
  }

  return { overlayOpen, closeGlassOverlays, closeGlassDialog, renderGlassOverlays };
}
