// Turn System Proxy off again through its visible switch. TUN Mode stays
// requested, so the coordinator retires the combined run, which restores this
// user's proxy options, and starts a Tunnel run on its own.
(async (page, observeNative) => {
  await page.locator('#nav button[data-page="general"]').click();
  const before = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  if (before.unavailable_reason !== null || before.snapshot.state.state !== 'tunnel_system_proxy_active' ||
      before.snapshot.desired_mode !== 'tunnel_system_proxy' || before.snapshot.state.runtime.ready !== true ||
      before.snapshot.state.runtime.owner !== 'windows_tunnel_service') {
    throw new Error(`The GUI's verified combined runtime is no longer active: ${JSON.stringify(before)}`);
  }
  const control = page.locator('label.inline-switch').filter({ has: page.locator('[data-toggle="systemProxy"]') });
  await control.click();
  // The observation runs inside the page, so the started generation is
  // passed in rather than captured.
  const tunnel = await observeNative(page, async (startedGeneration) => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    const state = value.snapshot.state.state;
    if (state === 'tunnel_active') {
      if (value.snapshot.desired_mode !== 'tunnel' || value.snapshot.state.runtime.ready !== true ||
          value.snapshot.state.runtime.owner !== 'windows_tunnel_service' ||
          value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest ||
          value.snapshot.generation <= startedGeneration) {
        throw new Error('System Proxy off did not hand over to a newer ready TUN runtime');
      }
      return value;
    }
    // The coordinator publishes Off between retiring both and starting TUN.
    if (!['tunnel_system_proxy_active', 'tunnel_stopping', 'off', 'tunnel_installing', 'tunnel_starting'].includes(state)) {
      throw new Error(`Unexpected combined stop result: ${JSON.stringify(value)}`);
    }
    return false;
  }, before.snapshot.generation, { name: 'combined stop', timeoutMs: 75000 });
  await observeNative(page, () => {
    const proxy = document.querySelector('[data-toggle="systemProxy"]');
    const tunnelSwitch = document.querySelector('[data-toggle="tunMode"]');
    return proxy && tunnelSwitch && !proxy.disabled && !proxy.checked && !tunnelSwitch.disabled && tunnelSwitch.checked
      ? { system_proxy_on: false, tunnel_on: true } : false;
  }, undefined, { name: 'switches after the combined mode', timeoutMs: 15000 });
  await page.screenshot({ path: 'combined-stopped.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  return { before, tunnel, snapshot, mutations: ['systemProxy:off'], release_accepted: false };
})
