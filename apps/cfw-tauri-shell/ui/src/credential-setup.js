// Credential setup for a profile: which of its credential references the
// vault is missing.
import { state } from "./state.js";
import { errorText, escapeHtml } from "./text-format.js";
import { invoke } from "./ipc.js";
import { t } from "./i18n.js";
import { appendLog } from "./app-log.js";
import {
  credentialLabel,
  credentialProvisionBatch,
  normalizeCredentialGcPreview,
  normalizeCredentialPresence,
  normalizeCredentialReceipt,
  normalizeCredentialReferences,
  normalizeGcReceipt,
} from "./credentials.js";
import { engineIsOff } from "./engine-identity.js";
import { REASONS } from "./reasons.js";

export function createCredentialSetup({ renderPage, renderGlassOverlays, closeGlassOverlays }) {
  /// Asks the vault which of a profile's immutable credential references are still
  /// missing, then opens the entry dialog. Nothing is assumed present or missing
  /// when the vault cannot answer.
  async function openCredentialSetup(id) {
    const profile = state.profiles.find((item) => item.id === id);
    if (!profile) throw new Error(t("profile not found: {id}", { id: id }));
    state.credentialSetup = null;
    state.glassDialog = { kind: "credentials", id };
    renderGlassOverlays();
    try {
      const requirements = normalizeCredentialReferences(
        await invoke("profile_credential_requirements", { id }),
      );
      let missing = [];
      let presentCount = 0;
      if (requirements.length) {
        const presence = normalizeCredentialPresence(
          await invoke("profile_credential_presence", { id }),
          requirements,
        );
        missing = presence.filter(({ present }) => !present).map(({ reference }) => reference);
        presentCount = requirements.length - missing.length;
      }
      state.credentialSetup = {
        profileId: id,
        profileName: profile.name,
        requiredCount: requirements.length,
        presentCount,
        missing,
        vaultAvailable: true,
        error: null,
      };
    } catch (error) {
      const message = errorText(error);
      state.credentialSetup = {
        profileId: id,
        profileName: profile.name,
        requiredCount: null,
        presentCount: null,
        missing: [],
        vaultAvailable: false,
        error: message,
      };
      appendLog("error", "credentials", t("Could not verify credentials for {name}: {message}", { name: profile.name, message: message }));
    }
    if (state.glassDialog?.kind === "credentials") renderGlassOverlays();
  }

  function renderCredentialsDialog() {
    const setup = state.credentialSetup;
    const body = !setup
      ? `<p class="glass-dialog-copy">${escapeHtml(t("Reading credential requirements…"))}</p>`
      : !setup.vaultAvailable
        ? `<p class="glass-dialog-copy">${escapeHtml(t("Credential presence could not be verified, so nothing is being requested and nothing is assumed missing: {error}", { error: setup.error ?? t("The credential vault is unavailable.") }))}</p>`
        : setup.missing.length === 0
          ? `<p class="glass-dialog-copy">${setup.requiredCount === 0
                ? t("This profile references no credentials.")
                : t("All {requiredCount} credential reference(s) are already present in the vault.", { requiredCount: setup.requiredCount })}</p>`
          : `
              <p class="glass-dialog-copy">${escapeHtml(t("{present} of {required} reference(s) are already present. Enter every missing value once; the batch goes straight to the signed native Keychain vault and is never written to the profile, the log, or the configuration digest.", { present: setup.presentCount, required: setup.requiredCount }))}</p>
              ${setup.missing.map((reference, index) => `
                <label>${escapeHtml(credentialLabel(reference.kind))}
                  <input type="password" autocomplete="new-password" data-credential-secret data-credential-index="${index}" aria-label="${escapeHtml(t("Secret for {credential}", { credential: credentialLabel(reference.kind) }))}" />
                </label>
              `).join("")}
            `;
    const canSubmit = Boolean(setup?.vaultAvailable && setup.missing.length && engineIsOff());
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Profile credentials"))}">
          <h3>${escapeHtml(t("Credentials"))}${setup?.profileName ? ` · ${escapeHtml(setup.profileName)}` : ""}</h3>
          ${body}
          ${setup?.missing?.length && !engineIsOff() ? `<p class="glass-dialog-copy">${escapeHtml(REASONS.engineNotOff)}</p>` : ""}
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-dismiss>${escapeHtml(t("Close"))}</button>
            ${canSubmit ? `<button type="button" class="glass-btn" data-glass-credentials-confirm="${escapeHtml(setup.profileId)}">${escapeHtml(t("Store credentials"))}</button>` : ""}
          </div>
        </div>
      `);
  }

  function renderCredentialCleanupDialog() {
    const preview = state.credentialGcPreview;
    const references = (preview?.orphanReferences ?? []).slice(0, 12)
      .map((reference) => `<li>${escapeHtml(credentialLabel(reference.kind))} · ${escapeHtml(reference.id)}</li>`)
      .join("");
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Credential cleanup"))}">
          <h3>${escapeHtml(t("Unused credentials"))}</h3>
          <p class="glass-dialog-copy">${preview
            ? escapeHtml(t("Unused Keychain entries: {count}. Cleanup revalidates the repository snapshot and the vault revision before one atomic deletion.", { count: preview.orphanCount }))
            : t("The credential vault has no unused references.")}</p>
          ${references ? `<ul class="glass-list">${references}</ul>` : ""}
          <div class="glass-dialog-actions">
            <button type="button" class="glass-btn ghost" data-glass-credential-gc-cancel>${escapeHtml(t("Close"))}</button>
            ${preview ? `<button type="button" class="glass-btn danger" data-glass-credential-gc-confirm>${escapeHtml(t("Delete unused credentials"))}</button>` : ""}
          </div>
        </div>
      `);
  }

  function bind() {
    document.querySelectorAll("[data-glass-credentials-confirm]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        const profileId = event.currentTarget.dataset.glassCredentialsConfirm;
        const setup = state.credentialSetup;
        if (!setup || setup.profileId !== profileId) return;
        const inputs = [...document.querySelectorAll("[data-credential-secret]")];
        const secrets = setup.missing.map((_reference, index) => inputs
          .find((input) => Number(input.dataset.credentialIndex) === index)?.value ?? "");
        let batch = [];
        try {
          batch = credentialProvisionBatch(setup.missing, secrets);
          const receipt = await invoke("provision_profile_credentials", {
            profileId,
            credentials: batch,
          });
          normalizeCredentialReceipt(receipt, profileId);
          appendLog("info", "credentials", t("Stored {count} credential reference(s) for {profileName}", { count: batch.length, profileName: setup.profileName }));
          closeGlassOverlays();
          state.credentialSetup = null;
        } catch (error) {
          appendLog("error", "credentials", errorText(error));
        } finally {
          // The secrets leave this renderer as soon as the vault has them.
          for (const entry of batch) entry.secret = "";
          for (const input of inputs) input.value = "";
        }
        renderPage();
      });
    });

    document.querySelectorAll("[data-glass-credential-gc-confirm]").forEach((button) => {
      button.addEventListener("click", async () => {
        const preview = state.credentialGcPreview;
        if (!preview) return;
        try {
          const receipt = await invoke("commit_credential_gc", { previewId: preview.previewId });
          normalizeGcReceipt(receipt, preview.orphanCount);
          appendLog("info", "credentials", t("Removed {removed_count} unused credential reference(s)", { removed_count: receipt.removed_count }));
        } catch (error) {
          appendLog("error", "credentials", errorText(error));
        } finally {
          // A preview is one-shot on the server: any rejection needs a new one.
          state.credentialGcPreview = null;
          closeGlassOverlays();
        }
        renderPage();
      });
    });

    document.querySelectorAll("[data-glass-credential-gc-cancel]").forEach((button) => {
      button.addEventListener("click", async () => {
        const preview = state.credentialGcPreview;
        state.credentialGcPreview = null;
        closeGlassOverlays();
        if (preview) {
          try {
            await invoke("cancel_credential_gc", { previewId: preview.previewId });
          } catch (error) {
            appendLog("error", "credentials", errorText(error));
          }
        }
        renderPage();
      });
    });
  }

  function render(dialog) {
    switch (dialog.kind) {
      case "credentials": return renderCredentialsDialog();
      case "credential-cleanup": return renderCredentialCleanupDialog();
      default: throw new TypeError(`credential dialog ${dialog.kind} is unknown`);
    }
  }

  const actions = {
    "preview-credential-gc": async () => {
      try {
        const preview = normalizeCredentialGcPreview(await invoke("preview_credential_gc"));
        state.credentialGcPreview = preview.orphanCount ? preview : null;
        state.glassDialog = { kind: "credential-cleanup" };
        renderGlassOverlays();
        return;
      } catch (error) {
        // A refusal, such as invalid profiles still listed, says what to do
        // next; it is shown where the cleanup was asked for, not only logged.
        appendLog("error", "credentials", errorText(error));
        state.glassDialog = {
          kind: "info",
          payload: { title: t("Unused credentials"), body: t("Credential cleanup is unavailable: {error}", { error: errorText(error) }) },
        };
        renderGlassOverlays();
        return;
      }
    },
  };

  return { openCredentialSetup, dialogs: { kinds: ["credentials", "credential-cleanup"], render, bind }, actions };
}
