/* TEST DATA transport only. The unmodified built frontend owns every page. */
(() => {
  let next = 1;
  const callbacks = new Map();
  let observationCount = 0;
  const bounded = (value, limit) => Array.from(String(value ?? '')).slice(0, limit).join('');
  function observe(kind, fields) {
    if (observationCount >= 1000) return;
    observationCount += 1;
    // Passive, bounded TEST DATA observation only. Never prevent, stop,
    // retarget, synthesize, or wait for a user's event.
    void window.webkit.messageHandlers.cfmIntegration.postMessage({
      command: 'component_test_observation', args: { kind, ...fields },
    }).catch((error) => console.warn('TEST DATA observer unavailable:', bounded(error?.message ?? error, 256)));
  }
  window.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : event.target?.parentElement;
    const page = target?.closest('[data-page]')?.dataset.page;
    const action = target?.closest('[data-action]')?.dataset.action;
    observe('click', { dataPage: page === undefined ? null : bounded(page, 64),
      dataAction: action === undefined ? null : bounded(action, 64) });
  }, { capture: true, passive: true });
  window.addEventListener('keydown', (event) => observe('keydown', { key: bounded(event.key, 64) }),
    { capture: true, passive: true });
  window.addEventListener('error', (event) => observe('error', { message: bounded(event.message, 512) }),
    { capture: true, passive: true });
  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason;
    observe('unhandledrejection', { message: bounded(reason?.message ?? reason, 512) });
  }, { capture: true, passive: true });
  Object.defineProperty(window, '__CFM_COMPONENT_TEST__', { value: Object.freeze({
    deliver(id, payload) { const entry = callbacks.get(id); if (!entry) throw new Error(`Missing test callback ${id}`); if (entry.once) callbacks.delete(id); entry.callback(payload); },
    callbackCount() { return callbacks.size; },
  }) });
  window.__TAURI_INTERNALS__ = {
    metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main' } },
    transformCallback(callback, once = false) { const id = next++; callbacks.set(id, { callback, once }); return id; },
    unregisterCallback(id) { callbacks.delete(id); },
    invoke(command, args = {}) {
      // JSON invokes the installed Tauri Channel.toJSON implementation, which
      // produces __CHANNEL__:id. No substitute Channel class is injected.
      return window.webkit.messageHandlers.cfmIntegration.postMessage(JSON.parse(JSON.stringify({command, args})));
    },
  };
  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener() {} };
})();
