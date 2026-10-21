// Stop the UI-owned core after the separate native HTTP probe has passed.
(async (page) => {
  const before = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  if (before.unavailable_reason !== null || before.snapshot.state.state !== 'local_proxy_active' ||
      before.snapshot.desired_mode !== 'local_proxy' || before.snapshot.state.runtime.ready !== true) {
    throw new Error(`The GUI's verified LocalProxy is no longer active: ${JSON.stringify(before)}`);
  }
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).click();
  const stoppedHandle = await page.waitForFunction(async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    const state = value.snapshot.state.state;
    if (state === 'off') {
      if (value.snapshot.desired_mode !== 'off') throw new Error('Stopped engine still has a pending desired mode');
      return value;
    }
    if (!['local_proxy_active', 'local_proxy_stopping'].includes(state)) throw new Error(`Unexpected stop result: ${JSON.stringify(value)}`);
    return false;
  }, undefined, { timeout: 30000, polling: 250 });
  let stopped;
  try { stopped = await stoppedHandle.jsonValue(); } finally { await stoppedHandle.dispose(); }
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Start core' }).waitFor();
  await page.screenshot({ path: 'local-proxy-stopped.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  await page.locator('#nav button[data-page="settings"]').click();
  await page.locator('[data-action="quit-app"]').waitFor();
  return { before, stopped, snapshot, mutations: ['toggle-core'], release_accepted: false };
})
