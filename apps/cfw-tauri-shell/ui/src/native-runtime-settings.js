import { t, getLocale } from "./i18n.js";

export function runtimeDialogFrame(dialog) {
  const draft = dialog.draft;
  return {
    locale: getLocale(), appearance: document.documentElement.dataset.theme,
    labels: {
      title: t("Network settings"),
      description: t("Changes apply to the current core. Existing connections may reconnect."),
      port: t("Local proxy port"), automatic: t("Automatic"), level: t("Log level"), mtu: "TUN MTU",
      ipv6DNS: t("Enable IPv6 DNS"),
      ipv6Note: t("Turn off for a proxy server with a broken IPv6 exit. TUN still captures IPv6 traffic."),
      allow: t("Share with trusted LAN devices"),
      lanNote: t("LAN devices use a separate port. Enter the private source networks allowed to use it."),
      lanAddress: t("LAN listener"), lanPort: t("LAN port"), lanSources: t("Trusted source ranges"),
      cancel: t("Cancel"), apply: t("Apply"), applying: t("Applying…"),
      transportFailure: t("The native settings window could not deliver this action. Close it and try again."),
      // Swift fills these parameters after enforcing the input resource bounds.
      inputTooLong: t("{label} must contain at most {maximum} characters", { label: "{label}", maximum: "{maximum}" }),
    },
    draft: { port: draft.port, level: draft.level, mtu: draft.mtu, ipv6DNS: draft.ipv6DNS,
      allow: draft.allow, lanAddress: draft.lanAddress, lanPort: draft.lanPort, lanSources: draft.lanSources,
      ipv6DNSEdited: !draft.ipv6DNSInherited },
    saving: dialog.saving, error: dialog.error,
  };
}

// This adapter owns window presentation only. Network validation, revisions,
// failure drafts and saving state remain in createRuntimeSettingsUI.
export function createNativeRuntimeSettings({ enabled, invoke, makeChannel, onError }) {
  let active = null;
  let pending = Promise.resolve();
  function enqueue(operation) {
    const result = pending.then(operation);
    // Preserve the rejected result for its caller while allowing cleanup to run.
    pending = result.then(() => undefined, () => undefined);
    return result;
  }
  async function dismiss(token) {
    if (!token.started || token.closed) return;
    await invoke("dismiss_native_runtime_settings", { requestId: token.requestId });
    token.closed = true;
  }
  function fail(token, error) {
    if (active !== token) return;
    token.failure = error instanceof Error ? error.message : String(error);
    void enqueue(() => dismiss(token)).catch(onError);
    onError(error);
    token.onChange();
  }
  function sync(dialog, frame, { onSubmit, onClose, onChange } = {}) {
    if (active && active.dialog !== dialog) {
      const previous = active;
      active = null;
      void enqueue(() => dismiss(previous)).catch(onError);
    }
    if (!dialog) return null;
    if (!active) {
      const token = { dialog, requestId: crypto.randomUUID(), sequence: 1, submission: 0, onChange, closed: false, failure: null };
      active = token;
      token.projection = JSON.stringify(frame);
      const request = { requestId: token.requestId, sequence: token.sequence, acknowledgedSubmission: token.submission, ...frame };
      void enqueue(async () => {
        if (active !== token) return;
        const completion = makeChannel((result) => {
          if (active !== token || token.closed) return;
          const keys = result && typeof result === "object" && !Array.isArray(result) ? Object.keys(result).sort().join(",") : "";
          if (!result || result.requestId !== token.requestId
            || !(result.kind === "closed" && keys === "kind,requestId"
              || result.kind === "submit" && keys === "draft,kind,requestId,submissionId"
                && Number.isSafeInteger(result.submissionId) && result.submissionId > token.submission)) {
            fail(token, new Error("Native settings returned an invalid result"));
            return;
          }
          if (result.kind === "closed") {
            token.closed = true;
            if (!token.failure) { active = null; onClose(); }
          } else {
            // The owner revalidates the complete draft and the current dialog.
            // Even an identical validation error must acknowledge this submit;
            // otherwise native pending state would wait forever for a new frame.
            token.submission = result.submissionId;
            token.needsAcknowledgement = true;
            Promise.resolve(onSubmit(result.draft)).catch((error) => fail(token, error));
          }
        });
        token.started = true;
        await invoke("present_native_runtime_settings", { request, completion });
        if (active !== token) await dismiss(token);
      }).catch((error) => fail(token, error));
      return null;
    }
    const token = active;
    if (token.failure) return token.failure;
    const projection = JSON.stringify(frame);
    if (projection !== token.projection || token.needsAcknowledgement) {
      token.needsAcknowledgement = false;
      token.projection = projection;
      const request = { requestId: token.requestId, sequence: ++token.sequence, acknowledgedSubmission: token.submission, ...frame };
      void enqueue(async () => {
        if (active === token && !token.closed && !token.failure) {
          await invoke("update_native_runtime_settings", { request });
        }
      }).catch((error) => fail(token, error));
    }
    return null;
  }
  return { enabled, sync };
}
