// A presentation adapter only. Business actions remain in the existing profile
// handlers and are never executed by the native menu or this transport.
export function profileMenuItems(actions, profile, { engineOff, engineNotOffReason, t }) {
  return actions.filter((action) => !(action.needsInactive && profile.active)).map((action) => {
    let reason = null;
    if (action.remoteOnly) {
      if (profile.sourceUrl === undefined) {
        reason = profile.sourceError
          ? t("Subscription URL could not be read: {sourceError}", { sourceError: profile.sourceError })
          : t("Reading this profile…");
      } else if (profile.sourceUrl === null) {
        reason = t("This profile was imported locally and has no subscription URL.");
      }
    }
    if (!reason && action.needsEngineOff && !engineOff) reason = engineNotOffReason;
    return { ...action, reason };
  });
}

export function nativeMenuItems(items) {
  return items.map((item) => ({ id: item.id, title: item.label, icon: item.icon,
    enabled: item.reason === null, reason: item.reason, danger: item.danger === true }));
}

export function createNativeProfileMenu({ invoke, makeChannel, onError }) {
  let active = null;
  let pending = Promise.resolve();
  // Serialize presentation messages only, never the profile's business work.
  // Each caller receives its rejection; this settled tail lets later closes run.
  function enqueue(work) {
    const result = pending.then(work);
    pending = result.then(() => undefined, () => undefined);
    return result;
  }
  function finish(token, result) {
    if (token.ended) return;
    token.ended = true;
    if (active === token) active = null;
    token.complete(result);
  }
  async function closeNative(token) {
    if (!token.started || token.nativeClosed) return false;
    const closed = await invoke("dismiss_native_profile_menu", { requestId: token.requestId });
    token.nativeClosed = true;
    return closed;
  }
  async function present(request, complete) {
    if (active) void dismiss().catch(onError);
    const token = { requestId: request.requestId, revision: request.revision, ready: false, ended: false, complete };
    active = token;
    const receive = (result) => {
      if (active !== token || token.ended) return;
      const valid = result && typeof result === "object" && !Array.isArray(result)
        && Object.keys(result).sort().join(",") === "action,error,requestId"
        && result.requestId === token.requestId
        && (result.action === null || typeof result.action === "string")
        && (result.error === null || (typeof result.error === "string" && result.error.length > 0))
        && !(result.error !== null && result.action !== null);
      if (!valid) {
        finish(token, { requestId: token.requestId, action: null, error: "Native profile menu returned an invalid result" });
        // Keep failures observable and let the caller decide how to surface it.
        void enqueue(() => closeNative(token)).catch(onError);
        return;
      }
      finish(token, result);
    };
    try {
      return await enqueue(async () => {
        if (active !== token || token.ended) return false;
        token.started = true;
        const completion = makeChannel(receive);
        await invoke("present_native_profile_menu", { request, completion });
        // A page change may cancel while the main-thread presentation is queued.
        // Close that exact request after acknowledgement, never a newer menu.
        if (active !== token || token.ended) {
          await closeNative(token);
          return false;
        }
        token.ready = true;
        return true;
      });
    } catch (error) {
      if (active === token) active = null;
      token.ended = true;
      throw error;
    }
  }
  async function update(request) {
    const token = active;
    if (!token || !token.ready || token.requestId !== request.requestId || request.revision <= token.revision) return false;
    token.revision = request.revision;
    return enqueue(() => active === token && !token.ended
      ? invoke("update_native_profile_menu", { request }) : false);
  }
  async function dismiss() {
    const token = active;
    if (!token) return false;
    // Cancel the intent immediately. Keep the channel registered until Rust
    // drops it, but ignore any selection already travelling back from the panel.
    finish(token, { requestId: token.requestId, action: null, error: null });
    return enqueue(() => closeNative(token));
  }
  return { present, update, dismiss };
}
