// WebView2 readiness precedes the coordinator's initial native reconciliation.
// Wait only for its exact initial sentinel; real startup failures remain errors.
(async (page, observeNative) => {
  // The shell is visible before NativeStartup admits IPC. The navigation is
  // rendered only after boot_payload succeeds; wait for that existing UI gate
  // before observing the separate coordinator reconciliation below.
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor({ timeout: 30000 });
  const engine = await observeNative(page, async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Startup observation unavailable: ${value.unavailable_reason}`);
    const snapshot = value.snapshot;
    const state = snapshot.state;
    if (snapshot.desired_mode === 'off' && state.state === 'off') return value;
    if (snapshot.desired_mode === 'off' && snapshot.config_digest === null &&
        state.state === 'failed' && state.target === 'off' && state.generation === snapshot.generation &&
        state.error === 'native startup reconciliation is pending' && state.recheck_pending === false &&
        value.startup_recovery_available === false) return false;
    throw new Error(`Unexpected native startup result: ${JSON.stringify(value)}`);
  }, undefined, { name: 'initial native Off reconciliation', timeoutMs: 30000 });
  return { engine, initial_off_verified: true, mutations: [], release_accepted: false };
})
