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
import { askForDialog } from "./dialog-requests.js";

export function createCredentialSetup({ renderPage, renderGlassOverlays, closeGlassOverlays }) {
  // The secrets typed in the dialog of credentials that is open, each for the
  // reference it was typed for. The page draws a dialog again from its state,
  // as every render of the page does while it is open, and a secret is kept
  // out of the state and of the markup: it is put back into the field of its
  // reference as the dialog is drawn for its profile, and let go once the
  // overlays are drawn without that dialog, dismissed or replaced, and once
  // the vault has had it.
  let typing = null;

  /// The secrets typed in `dialog` while it is the dialog of credentials that
  /// is open. Those of any other dialog are let go.
  function secretsTypedIn(dialog) {
    if (typing?.dialog !== dialog) typing = dialog?.kind === "credentials" ? { dialog, secrets: new Map() } : null;
    return typing?.secrets ?? null;
  }

  /// Opens the entry dialog of a profile's credentials and asks the vault which
  /// of its immutable references are still missing. Nothing is assumed present
  /// or missing when the vault cannot answer. The answer is shown in that
  /// dialog while it is open, and in no other: once it was closed, the dialog of
  /// another profile may be open, whose secrets would be stored for this one.
  async function openCredentialSetup(id) {
    const profile = state.profiles.find((item) => item.id === id);
    if (!profile) throw new Error(t("profile not found: {id}", { id: id }));
    state.credentialSetup = null;
    const dialog = { kind: "credentials", id };
    state.glassDialog = dialog;
    renderGlassOverlays();
    let setup;
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
      setup = {
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
      setup = {
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
    if (state.glassDialog !== dialog) return;
    state.credentialSetup = setup;
    renderGlassOverlays();
  }

  function renderCredentialsDialog() {
    const setup = state.credentialSetup;
    const windows = state.payload?.product?.operating_system === "windows";
    const body = !setup
      ? `<p class="glass-dialog-copy">${escapeHtml(t("Reading credential requirements…"))}</p>`
      : !setup.vaultAvailable
        ? `<p class="glass-dialog-copy">${escapeHtml(t("Credential presence could not be verified, so nothing is being requested and nothing is assumed missing: {error}", { error: setup.error ?? t("The credential vault is unavailable.") }))}</p>`
        : setup.missing.length === 0
          ? `<p class="glass-dialog-copy">${setup.requiredCount === 0
                ? t("This profile references no credentials.")
                : t("All {requiredCount} credential reference(s) are already present in the vault.", { requiredCount: setup.requiredCount })}</p>`
          : `
              <p class="glass-dialog-copy">${escapeHtml(windows
                ? t("{present} of {required} reference(s) are already present. Enter every missing value once; the batch goes straight to Windows protected storage and is never written to the profile, the log, or the configuration digest.", { present: setup.presentCount, required: setup.requiredCount })
                : t("{present} of {required} reference(s) are already present. Enter every missing value once; the batch goes straight to the signed native Keychain vault and is never written to the profile, the log, or the configuration digest.", { present: setup.presentCount, required: setup.requiredCount }))}</p>
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
    const windows = state.payload?.product?.operating_system === "windows";
    const references = (preview?.orphanReferences ?? []).slice(0, 12)
      .map((reference) => `<li>${escapeHtml(credentialLabel(reference.kind))} · ${escapeHtml(reference.id)}</li>`)
      .join("");
    return (`
        <div class="glass-dialog-backdrop" data-glass-dismiss></div>
        <div class="glass-dialog" role="dialog" aria-label="${escapeHtml(t("Credential cleanup"))}">
          <h3>${escapeHtml(t("Unused credentials"))}</h3>
          <p class="glass-dialog-copy">${preview
            ? escapeHtml(windows
              ? t("Unused protected credentials: {count}. Cleanup revalidates the repository snapshot and the vault revision before one atomic deletion.", { count: preview.orphanCount })
              : t("Unused Keychain entries: {count}. Cleanup revalidates the repository snapshot and the vault revision before one atomic deletion.", { count: preview.orphanCount }))
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
    const typedIn = state.glassDialog;
    const typed = secretsTypedIn(typedIn);
    const shown = state.credentialSetup;
    if (typed && shown?.profileId === typedIn.id) {
      document.querySelectorAll("[data-credential-secret]").forEach((field) => {
        const { id } = shown.missing[Number(field.dataset.credentialIndex)];
        field.value = typed.get(id) ?? "";
        field.addEventListener("input", () => { typed.set(id, field.value); });
      });
    }
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
          if (typing?.dialog === typedIn) typing = null;
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
        if (preview) await cancelCleanup(preview.previewId);
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

  /// Cancels the cleanup that the host keeps for the preview `previewId`. A
  /// failure is logged.
  async function cancelCleanup(previewId) {
    try {
      await invoke("cancel_credential_gc", { previewId });
    } catch (error) {
      appendLog("error", "credentials", errorText(error));
    }
  }

  // The read of a review under way, and how many presses wait for it.
  let previewing = null;
  const actions = {
    // The review reads before it opens, so it is asked for at the press and
    // opens only while it is the dialog that was asked for last. The host
    // reads one review at a time and refuses another meanwhile, so a press
    // while the read of an earlier one is under way joins that read: as the
    // dialog asked for last, it would show its own refusal in place of the
    // preview that was read. The host keeps the cleanup of a preview until it
    // is cancelled or another preview replaces it. The presses that joined a
    // read have its answer in the order they were made, the one asked for
    // last among them last, so the last of them cancels a cleanup that none
    // of them shows.
    "preview-credential-gc": async () => {
      const latest = askForDialog(state);
      const joined = previewing !== null;
      try {
        previewing ??= { read: invoke("preview_credential_gc").finally(() => { previewing = null; }), waiting: 0 };
        const review = previewing;
        review.waiting += 1;
        const preview = normalizeCredentialGcPreview(await review.read);
        review.waiting -= 1;
        if (latest()) {
          state.credentialGcPreview = preview.orphanCount ? preview : null;
          state.glassDialog = { kind: "credential-cleanup" };
          renderGlassOverlays();
        } else if (review.waiting === 0 && preview.orphanCount) {
          await cancelCleanup(preview.previewId);
        }
        return;
      } catch (error) {
        // A refusal, such as invalid profiles still listed, says what to do
        // next; it is shown where the cleanup was asked for, not only logged.
        if (!joined) appendLog("error", "credentials", errorText(error));
        if (!latest()) return;
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
