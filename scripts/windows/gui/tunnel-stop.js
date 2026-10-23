// Turn TUN Mode off through its visible switch. Removing the last
// integration keeps the ready core as a local proxy, so SYSTEM retires the
// tunnel adapter while a LocalProxy runtime takes over.
(async (page, observeNative) => {
  await page.locator('#nav button[data-page="general"]').click();
  const before = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  if (before.unavailable_reason !== null || before.snapshot.state.state !== 'tunnel_active' ||
      before.snapshot.desired_mode !== 'tunnel' || before.snapshot.state.runtime.ready !== true ||
      before.snapshot.state.runtime.owner !== 'windows_tunnel_service') {
    throw new Error(`The GUI's verified TUN runtime is no longer active: ${JSON.stringify(before)}`);
  }
  const control = page.locator('label.inline-switch').filter({ has: page.locator('[data-toggle="tunMode"]') });
  await control.click();
  const local = await observeNative(page, async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    const state = value.snapshot.state.state;
    if (state === 'local_proxy_active') {
      if (value.snapshot.desired_mode !== 'local_proxy' || value.snapshot.state.runtime.ready !== true ||
          value.snapshot.state.runtime.owner !== 'windows_user_agent' ||
          value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest ||
          value.snapshot.generation <= before.snapshot.generation) {
        throw new Error('TUN Mode off did not hand over to a newer ready local core');
      }
      return value;
    }
    // The coordinator publishes Off between retiring TUN and starting the core.
    if (!['tunnel_active', 'tunnel_stopping', 'off', 'local_proxy_starting'].includes(state)) {
      throw new Error(`Unexpected TUN stop result: ${JSON.stringify(value)}`);
    }
    return false;
  }, undefined, { name: 'TUN stop', timeoutMs: 30000 });
  await observeNative(page, () => {
    const input = document.querySelector('[data-toggle="tunMode"]');
    return input && !input.disabled && !input.checked ? { enabled: true, checked: false } : false;
  }, undefined, { name: 'TUN switch after stop', timeoutMs: 15000 });
  await page.screenshot({ path: 'tunnel-stopped.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  return { before, local, snapshot, mutations: ['tunMode:off'], release_accepted: false };
})
