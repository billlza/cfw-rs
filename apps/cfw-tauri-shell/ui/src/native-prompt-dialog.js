import { t, getLocale } from "./i18n.js";

// Text bounds of the native frame in Unicode scalar values, and a byte budget
// under its 16384-byte limit that leaves room for the request and session
// identity added around the frame.
const TITLE_SCALARS = 160;
const MESSAGE_SCALARS = 4096;
const FRAME_BYTES = 16_000;

// A scalar takes at most two UTF-16 units, so a longer string is refused
// before it is expanded. A lone surrogate has no UTF-8 form for the host.
const within = (text, limit) => typeof text === "string" && text.length <= 2 * limit
  && text.isWellFormed() && Array.from(text).length <= limit;
const titled = (text) => within(text, TITLE_SCALARS) && text.trim() !== "";

/// The frame for a prompt the native panel can carry, or null when its text is
/// outside the bounded wire contract or the page theme is not resolved yet.
/// The caller keeps its web dialog for such a prompt, so the presentation
/// never cuts or refuses what it has to say.
export function promptDialogFrame(prompt) {
  const appearance = document.documentElement.dataset.theme;
  if (appearance !== "light" && appearance !== "dark") return null;
  if (!titled(prompt.title) || !within(prompt.message, MESSAGE_SCALARS)
    || !prompt.buttons.every((button) => titled(button.title))) return null;
  const frame = {
    locale: getLocale(), appearance,
    title: prompt.title, message: prompt.message,
    buttons: prompt.buttons.map(({ id, title, role }) => ({ id, title, role })),
    transportFailure: t("The native dialog could not deliver this action. Close it and try again."),
  };
  return new TextEncoder().encode(JSON.stringify(frame)).length <= FRAME_BYTES ? frame : null;
}

// This adapter owns window presentation only. Which dialog is open, what a
// button does and whether that succeeded remain with the dashboard.
export function createNativePromptDialog({ enabled, invoke, makeChannel, onError }) {
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
    await invoke("dismiss_native_prompt_dialog", { requestId: token.requestId });
    token.closed = true;
  }
  function fail(token, error) {
    onError(error, token.title);
    // A dialog the dashboard already closed is reported, with nothing left to show.
    if (active !== token) return;
    token.failure = error instanceof Error ? error.message : String(error);
    void enqueue(() => dismiss(token)).catch((failure) => onError(failure, token.title));
    token.onChange();
  }
  function receive(token, result, { onActivate, onClose }) {
    // A failed dialog offers dismissal only. Its panel may still be on screen
    // until that dismissal lands, and nothing it reports can act any more.
    if (active !== token || token.closed || token.failure) return;
    const keys = result && typeof result === "object" && !Array.isArray(result) ? Object.keys(result).sort().join(",") : "";
    const closed = result?.kind === "closed" && keys === "kind,requestId";
    // The panel reports one activation at a time, for a button of the frame
    // it shows, and keeps its actions unavailable until that one is acknowledged.
    const activated = result?.kind === "activate" && keys === "buttonId,kind,requestId,submissionId"
      && Number.isSafeInteger(result.submissionId) && result.submissionId > token.received
      && token.received === token.acknowledged && token.activatable.includes(result.buttonId);
    if (result?.requestId !== token.requestId || !(closed || activated)) {
      fail(token, new Error("Native prompt dialog returned an invalid result"));
      return;
    }
    if (closed) {
      token.closed = true;
      active = null;
      onClose();
      return;
    }
    token.received = result.submissionId;
    // Acknowledge only when the dashboard has finished with the action, so
    // the panel cannot repeat it while it is still running.
    (async () => onActivate(result.buttonId))().then(() => {
      if (active !== token || token.failure) return;
      token.acknowledged = result.submissionId;
      token.needsAcknowledgement = true;
      token.onChange();
    }, (error) => fail(token, error));
  }
  function sync(dialog, frame, { onActivate, onClose, onChange } = {}) {
    if (active && active.dialog !== dialog) {
      const previous = active;
      active = null;
      void enqueue(() => dismiss(previous)).catch((error) => onError(error, previous.title));
    }
    if (!dialog) return null;
    const activatable = frame.buttons.filter(({ role }) => role !== "cancel").map(({ id }) => id);
    if (!active) {
      const token = { dialog, requestId: crypto.randomUUID(), sequence: 1, received: 0, acknowledged: 0,
        title: frame.title, activatable, onChange, closed: false, failure: null };
      active = token;
      token.projection = JSON.stringify(frame);
      const request = { requestId: token.requestId, sequence: token.sequence, acknowledgedSubmission: token.acknowledged, ...frame };
      void enqueue(async () => {
        if (active !== token) return;
        const completion = makeChannel((result) => receive(token, result, { onActivate, onClose }));
        token.started = true;
        // A dialog closed meanwhile is dismissed by the operation queued behind this one.
        await invoke("present_native_prompt_dialog", { request, completion });
      }).catch((error) => fail(token, error));
      return null;
    }
    const token = active;
    if (token.failure) return token.failure;
    const projection = JSON.stringify(frame);
    if (projection !== token.projection || token.needsAcknowledgement) {
      token.needsAcknowledgement = false;
      token.projection = projection;
      token.title = frame.title;
      token.activatable = activatable;
      const request = { requestId: token.requestId, sequence: ++token.sequence, acknowledgedSubmission: token.acknowledged, ...frame };
      void enqueue(async () => {
        if (active === token && !token.closed && !token.failure) {
          await invoke("update_native_prompt_dialog", { request });
        }
      }).catch((error) => fail(token, error));
    }
    return null;
  }
  return { enabled, sync };
}
